"""Integration tests for the auth endpoints."""


def _code_from_signup(response) -> str:
    # Signup returns "... Dev verification code: XXXXXX"
    return response.json()["message"].split(": ")[-1]


async def _register_and_verify(client, email="user@example.com", password="password123"):
    resp = await client.post("/auth/signup", json={"email": email, "password": password})
    code = _code_from_signup(resp)
    await client.post("/auth/verify", json={"email": email, "code": code})


async def test_signup_returns_verification_code(client):
    resp = await client.post("/auth/signup", json={"email": "a@b.com", "password": "password123"})
    assert resp.status_code == 201
    assert "verification code" in resp.json()["message"].lower()


async def test_signup_rejects_duplicate_email(client):
    payload = {"email": "dup@b.com", "password": "password123"}
    await client.post("/auth/signup", json=payload)
    resp = await client.post("/auth/signup", json=payload)
    assert resp.status_code == 400


async def test_verify_success(client):
    resp = await client.post("/auth/signup", json={"email": "v@b.com", "password": "password123"})
    code = _code_from_signup(resp)
    resp = await client.post("/auth/verify", json={"email": "v@b.com", "code": code})
    assert resp.status_code == 200


async def test_verify_wrong_code(client):
    await client.post("/auth/signup", json={"email": "w@b.com", "password": "password123"})
    resp = await client.post("/auth/verify", json={"email": "w@b.com", "code": "000000"})
    assert resp.status_code == 400


async def test_login_requires_verification(client):
    await client.post("/auth/signup", json={"email": "u@b.com", "password": "password123"})
    resp = await client.post("/auth/login", json={"email": "u@b.com", "password": "password123"})
    assert resp.status_code == 400


async def test_login_success_returns_tokens(client):
    await _register_and_verify(client, "ok@b.com")
    resp = await client.post("/auth/login", json={"email": "ok@b.com", "password": "password123"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


async def test_login_wrong_password(client):
    await _register_and_verify(client, "pw@b.com")
    resp = await client.post("/auth/login", json={"email": "pw@b.com", "password": "nope"})
    assert resp.status_code == 401


async def test_refresh_rotates_and_revokes_old_token(client):
    await _register_and_verify(client, "rot@b.com")
    tokens = (await client.post("/auth/login", json={"email": "rot@b.com", "password": "password123"})).json()
    old_refresh = tokens["refresh_token"]

    resp = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != old_refresh

    # The rotated (old) token must no longer be accepted.
    assert (await client.post("/auth/refresh", json={"refresh_token": old_refresh})).status_code == 401
    # The new token still works.
    assert (await client.post("/auth/refresh", json={"refresh_token": new_refresh})).status_code == 200


async def test_refresh_rejects_access_token(client):
    await _register_and_verify(client, "acc@b.com")
    tokens = (await client.post("/auth/login", json={"email": "acc@b.com", "password": "password123"})).json()
    resp = await client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert resp.status_code == 401


async def test_refresh_rejects_garbage(client):
    assert (await client.post("/auth/refresh", json={"refresh_token": "x.y.z"})).status_code == 401
