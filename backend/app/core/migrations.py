from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from app.core.database import Base, engine
from app.models import entities  # noqa: F401


MODEL_TABLES = set(Base.metadata.tables)


def _alembic_config() -> Config:
    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations"))
    return config


def _stamp_existing_schema(config: Config) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "alembic_version" in table_names or not MODEL_TABLES.intersection(table_names):
        return

    missing_tables = sorted(MODEL_TABLES - table_names)
    if missing_tables:
        raise RuntimeError(
            "Database has a partial unmanaged schema. "
            f"Missing tables before Alembic stamp: {', '.join(missing_tables)}"
        )

    command.stamp(config, "head")


def run_migrations() -> None:
    config = _alembic_config()
    with engine.begin() as connection:
        connection.execute(text("SELECT 1"))
    _stamp_existing_schema(config)
    command.upgrade(config, "head")
