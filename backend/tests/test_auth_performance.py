"""Isolated API/database contracts; no operator database or network targets."""
import asyncio
import threading

from sqlalchemy import event, select
from starlette.requests import Request
from starlette.responses import Response

from app import main
from app.models import User, UserSession, utc_now


def middleware_request(client, headers, method="GET"):
    return Request({
        "type": "http", "app": client.app, "method": method,
        "path": "/api/test-auth-contract", "query_string": b"",
        "scheme": "http", "server": ("localhost", 8000),
        "client": ("testclient", 1234), "http_version": "1.1",
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
    })


def test_authentication_uses_one_select(client, admin_headers):
    engine = client.app.state.session_factory.kw["bind"]
    statements = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    async def endpoint(request):
        assert request.state.user.role == "ADMIN"
        return Response(status_code=200)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = asyncio.run(main.authenticate_request(middleware_request(client, admin_headers), endpoint))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200
    print(f"Authentication SELECT statements: {len(statements)}")
    assert len(statements) == 1


def test_authentication_releases_connection_before_endpoint(client, admin_headers):
    engine = client.app.state.session_factory.kw["bind"]

    async def endpoint(request):
        held = engine.pool.checkedout()
        print(f"Authentication connections held during endpoint: {held}")
        assert held == 0
        assert request.state.user.username == "test-admin"
        await asyncio.sleep(0)
        return Response(status_code=200)

    asyncio.run(main.authenticate_request(middleware_request(client, admin_headers), endpoint))
    assert engine.pool.checkedout() == 0


def test_authentication_database_io_is_off_event_loop(client, admin_headers):
    engine = client.app.state.session_factory.kw["bind"]
    event_loop_thread = threading.get_ident()
    database_threads = []

    def capture(*_args):
        database_threads.append(threading.get_ident())

    async def endpoint(_request):
        return Response(status_code=200)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        asyncio.run(main.authenticate_request(middleware_request(client, admin_headers), endpoint))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert database_threads
    assert event_loop_thread not in database_threads


def test_role_changes_are_not_cached(client, admin_headers):
    created = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "changing-operator", "password": "synthetic-operator-password", "role": "OPERATOR",
    })
    token = client.post("/api/auth/login", json={
        "username": "changing-operator", "password": "synthetic-operator-password",
    }).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/devices", headers=headers).status_code == 200
    assert client.put(f"/api/auth/users/{created.json()['id']}", headers=admin_headers, json={
        "role": "VIEWER", "is_active": True,
    }).status_code == 200
    assert client.post("/api/scheduler/pause", headers=headers).status_code == 403


def test_revocation_expiry_and_inactive_user_reject_without_dispatch(client, admin_headers):
    from datetime import timedelta

    async def forbidden(_request):
        raise AssertionError("Invalid identity reached endpoint")

    with client.app.state.session_factory() as db:
        session = db.scalar(select(UserSession))
        session.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    assert asyncio.run(main.authenticate_request(middleware_request(client, admin_headers), forbidden)).status_code == 401
    with client.app.state.session_factory() as db:
        assert db.scalar(select(UserSession)) is None
        user = db.scalar(select(User))
        user.is_active = False
        from app.services.auth_service import create_session
        token, _session = create_session(user, db)
    headers = {"Authorization": f"Bearer {token}"}
    assert asyncio.run(main.authenticate_request(middleware_request(client, headers), forbidden)).status_code == 401
    with client.app.state.session_factory() as db:
        assert db.scalar(select(UserSession)) is None


def test_audit_write_uses_short_worker_session(client, admin_headers):
    engine = client.app.state.session_factory.kw["bind"]
    event_loop_thread = threading.get_ident()
    writes = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("INSERT INTO audit_events".upper()):
            writes.append(threading.get_ident())

    async def endpoint(_request):
        assert engine.pool.checkedout() == 0
        return Response(status_code=202)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = asyncio.run(main.authenticate_request(middleware_request(client, admin_headers, "POST"), endpoint))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 202
    assert writes and event_loop_thread not in writes
    assert engine.pool.checkedout() == 0
    audit = client.get("/api/auth/audit-events", headers=admin_headers).json()
    entry = next(item for item in audit if item["path"] == "/api/test-auth-contract")
    assert (entry["username"], entry["role"], entry["status_code"]) == ("test-admin", "ADMIN", 202)
