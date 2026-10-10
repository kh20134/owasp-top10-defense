import pytest

from app import create_app


@pytest.fixture
def app():
    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


ALICE = {"username": "alice", "password": "alice-lab-pass"}
BOB = {"username": "bob", "password": "bob-lab-pass"}
