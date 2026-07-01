"""Integration tests for the user-management endpoints and role guards."""

from app.core.security import create_refresh_token
from app.modules.users.models import UserRole


async def test_me_requires_authentication(client):
    assert (await client.get("/me")).status_code == 401


async def test_me_returns_profile(client, make_user, auth_header):
    user = await make_user(email="me@b.com")
    resp = await client.get("/me", headers=auth_header(user.id))
    assert resp.status_code == 200
    assert resp.json()["email"] == "me@b.com"


async def test_me_rejects_refresh_token(client, make_user):
    user = await make_user(email="rt@b.com")
    headers = {"Authorization": f"Bearer {create_refresh_token(user.id)}"}
    assert (await client.get("/me", headers=headers)).status_code == 401


async def test_list_users_forbidden_for_regular_user(client, make_user, auth_header):
    user = await make_user()
    assert (await client.get("/users", headers=auth_header(user.id))).status_code == 403


async def test_admin_can_list_users(client, make_user, auth_header):
    admin = await make_user(email="admin@b.com", role=UserRole.ADMIN)
    await make_user(email="other@b.com")
    resp = await client.get("/users", headers=auth_header(admin.id))
    assert resp.status_code == 200
    assert len(resp.json()) == 2


async def test_admin_get_user_and_404(client, make_user, auth_header):
    admin = await make_user(email="admin@b.com", role=UserRole.ADMIN)
    assert (await client.get(f"/users/{admin.id}", headers=auth_header(admin.id))).status_code == 200
    assert (await client.get("/users/999999", headers=auth_header(admin.id))).status_code == 404


async def test_user_can_patch_self(client, make_user, auth_header):
    user = await make_user(email="self@b.com")
    resp = await client.patch(f"/users/{user.id}", json={"first_name": "Neo"}, headers=auth_header(user.id))
    assert resp.status_code == 200
    assert resp.json()["first_name"] == "Neo"


async def test_user_cannot_patch_others(client, make_user, auth_header):
    user = await make_user(email="u1@b.com")
    victim = await make_user(email="u2@b.com")
    resp = await client.patch(
        f"/users/{victim.id}", json={"first_name": "Hacked"}, headers=auth_header(user.id)
    )
    assert resp.status_code == 403


async def test_admin_can_delete_user(client, make_user, auth_header):
    admin = await make_user(email="admin@b.com", role=UserRole.ADMIN)
    target = await make_user(email="del@b.com")
    resp = await client.delete(f"/users/{target.id}", headers=auth_header(admin.id))
    assert resp.status_code == 200
    assert (await client.get(f"/users/{target.id}", headers=auth_header(admin.id))).status_code == 404
