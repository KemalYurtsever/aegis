from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from app.database import Base, create_database_engine, ensure_performance_indexes
from app.routers.system import database_readiness_component


def test_existing_databases_receive_monitoring_aggregation_index(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'performance.db'}")
    Base.metadata.create_all(bind=engine)

    ensure_performance_indexes(engine)

    index_names = {index["name"] for index in inspect(engine).get_indexes("monitor_results")}
    assert "ix_monitor_results_device_status" in index_names
    engine.dispose()


def test_existing_databases_receive_local_cve_version_index(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'performance.db'}")
    Base.metadata.create_all(bind=engine)

    ensure_performance_indexes(engine)

    index_names = {index["name"] for index in inspect(engine).get_indexes("local_cve_cpe_matches")}
    assert "ix_local_cve_cpe_product_version" in index_names
    engine.dispose()


def test_database_readiness_does_not_run_full_integrity_scan(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'readiness.db'}")
    Base.metadata.create_all(bind=engine)
    statements = []

    def capture_statement(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement.casefold())

    event.listen(engine, "before_cursor_execute", capture_statement)
    try:
        with Session(engine) as db:
            component = database_readiness_component(db)
    finally:
        event.remove(engine, "before_cursor_execute", capture_statement)

    assert component.status == "HEALTHY"
    assert "Connection ready" in component.message
    assert not any("quick_check" in statement for statement in statements)
    assert not any("foreign_key_check" in statement for statement in statements)
    engine.dispose()
