"""Database setup. SQLite by default, Postgres via DATABASE_URL."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create missing tables, and keep Alembic's bookkeeping in step.

    create_all() builds the current schema but doesn't record a migration
    revision, so a later `alembic upgrade head` (run on every deploy) would try
    to create the same tables again and crash. When the database has no
    alembic_version yet, stamp it at head: create_all just built that schema."""
    from pathlib import Path

    from sqlalchemy import inspect

    from . import models  # noqa: F401  (register models)

    had_version = "alembic_version" in inspect(engine).get_table_names()
    Base.metadata.create_all(bind=engine)
    if had_version:
        return
    ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    if not ini.exists():
        return
    try:
        from alembic import command
        from alembic.config import Config

        cfg = Config(str(ini))
        cfg.set_main_option("script_location", str(ini.parent / "alembic"))
        cfg.attributes["configure_logger"] = False
        command.stamp(cfg, "head")
    except Exception:  # bookkeeping only: never block startup
        import logging
        logging.getLogger("phishlens").warning("could not stamp alembic revision", exc_info=True)
