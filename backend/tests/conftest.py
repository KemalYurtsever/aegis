import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.database import Base, create_database_engine, get_db
from app.main import app
from app.services.backup_service import BackupService


@pytest.fixture
def client(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'test.db'}"
    test_engine = create_database_engine(database_url)
    testing_session = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    # Unit/API tests control monitoring explicitly and must never ping devices
    # from the developer's real local database in a background task.
    app.state.scheduler_enabled = False
    app.state.auth_required = False
    app.state.session_factory = testing_session
    app.state.backup_enabled = False
    app.state.backup_service = BackupService(database_url, tmp_path / "backups", keep_count=3)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    del app.state.scheduler_enabled
    del app.state.auth_required
    del app.state.session_factory
    del app.state.backup_enabled
    del app.state.backup_service
    del app.state.backup_scheduler
    test_engine.dispose()
