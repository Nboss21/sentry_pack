from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.listeners import router
from core.listener_manager import ListenerManager
from core.listener_registry import ListenerRegistry
from modules.c2.listeners.test_listener.listener import TestListener


def create_test_app() -> tuple[FastAPI, ListenerManager]:
    registry = ListenerRegistry()
    manager = ListenerManager(registry)

    app = FastAPI()
    app.include_router(
        router,
        prefix="/api/listeners",
    )

    return app, manager


def test_list_listeners(monkeypatch):
    app, manager = create_test_app()

    listener = TestListener()
    manager.register(listener)

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.get("/api/listeners")

    assert response.status_code == 200
    assert response.json() == {
        "listeners": [
            {
                "id": "test",
                "running": False,
            }
        ],
        "count": 1,
    }


def test_get_listener(monkeypatch):
    app, manager = create_test_app()

    manager.register(TestListener())

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.get("/api/listeners/test")

    assert response.status_code == 200
    assert response.json() == {
        "id": "test",
        "running": False,
    }


def test_get_unknown_listener(monkeypatch):
    app, manager = create_test_app()

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.get("/api/listeners/does-not-exist")

    assert response.status_code == 404


def test_start_listener(monkeypatch):
    app, manager = create_test_app()

    listener = TestListener()
    manager.register(listener)

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.post(
        "/api/listeners/test/start",
        json={
            "config": {},
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": "test",
        "running": True,
    }

    assert listener.is_running() is True


def test_start_listener_already_running(monkeypatch):
    app, manager = create_test_app()

    listener = TestListener()
    manager.register(listener)
    listener.start({}, lambda connection: None)

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.post(
        "/api/listeners/test/start",
        json={
            "config": {},
        },
    )

    assert response.status_code == 409


def test_stop_listener(monkeypatch):
    app, manager = create_test_app()

    listener = TestListener()
    manager.register(listener)
    listener.start({}, lambda connection: None)

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.post(
        "/api/listeners/test/stop",
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": "test",
        "running": False,
    }

    assert listener.is_running() is False


def test_stop_listener_not_running(monkeypatch):
    app, manager = create_test_app()

    manager.register(TestListener())

    monkeypatch.setattr(
        "api.routes.listeners.listener_manager",
        manager,
    )

    client = TestClient(app)

    response = client.post(
        "/api/listeners/test/stop",
    )

    assert response.status_code == 409