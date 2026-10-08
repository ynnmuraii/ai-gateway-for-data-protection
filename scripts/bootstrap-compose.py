"""Installation job: migrate, seed once, and grant a non-owning runtime role."""

import os
from pathlib import Path

import psycopg
from gateway.db import bootstrap, make_engine, migrate
from gateway.security import digest
from gateway.settings import Settings
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


def main():
    config = Settings()
    engine = make_engine(
        config.model_copy(update={"database_url": os.environ["GATEWAY_INSTALL_DATABASE_URL"]})
    )
    try:
        migrate(engine)
        with engine.connect() as connection:
            initialized = connection.execute(text("SELECT EXISTS (SELECT 1 FROM users)")).scalar_one()
        key = os.environ["GATEWAY_BOOTSTRAP_INTEGRATION_KEY"]
        if not initialized:
            bootstrap(
                engine,
                config,
                os.environ["GATEWAY_BOOTSTRAP_USERNAME"],
                os.environ["GATEWAY_BOOTSTRAP_PASSWORD"],
                key,
                external_subject="compose-unmapped",
            )
        else:
            with engine.connect() as connection:
                if not connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM client_integrations "
                        "WHERE bearer_key_hash=:hash AND enabled)"
                    ),
                    {"hash": digest(key)},
                ).scalar_one():
                    raise RuntimeError(
                        "Integration configuration does not match the initialized installation."
                    )
        owner_url = os.environ["GATEWAY_INSTALL_DATABASE_URL"].replace(
            "postgresql+psycopg://", "postgresql://"
        )
        with psycopg.connect(owner_url) as connection:
            resource = Path(__file__).resolve().parents[1] / "backend/migrations/provision_roles.sql"
            connection.execute(resource.read_text("utf-8"), prepare=False)
            connection.execute(
                sql.SQL("ALTER ROLE gateway_runtime PASSWORD {}").format(
                    sql.Literal(os.environ["GATEWAY_RUNTIME_PASSWORD"])
                )
            )
        print(
            "Database installed; runtime privileges provisioned. Connect Open WebUI to authorize its demo user."
        )
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, RuntimeError, SQLAlchemyError, psycopg.Error):
        raise SystemExit(
            "Database installation failed; verify deployment configuration. No credentials were logged."
        ) from None
