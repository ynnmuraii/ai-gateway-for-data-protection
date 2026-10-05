"""Installation-only commands; credentials never appear in process arguments."""
import argparse
import getpass
import os
import secrets
import sys

from psycopg import Error as PostgreSQLError
from sqlalchemy.exc import SQLAlchemyError

from .db import bootstrap, make_engine, migrate, reset_admin
from .settings import Settings


def main():
    parser = argparse.ArgumentParser(description="Manage the local AI gateway installation.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate")
    install = commands.add_parser("bootstrap")
    install.add_argument("--username", default="admin")
    install.add_argument("--external-subject", default="demo-user")
    install.add_argument("--generate", action="store_true", help="Generate credentials and display once on this terminal.")
    reset = commands.add_parser("reset-admin")
    reset.add_argument("--username", default="admin")
    args = parser.parse_args()
    engine = None
    try:
        settings = Settings()
        engine = make_engine(settings)
        if args.command == "migrate":
            migrate(engine)
            print("Database migration completed.")
            return
        password = os.environ.get("GATEWAY_BOOTSTRAP_PASSWORD")
        key = os.environ.get("GATEWAY_BOOTSTRAP_INTEGRATION_KEY")
        if args.command == "bootstrap" and args.generate:
            if not sys.stdout.isatty():
                parser.error("Generated credentials require an interactive terminal; use environment variables for automation.")
            password, key = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        elif password is None:
            if not sys.stdin.isatty():
                parser.error("Set GATEWAY_BOOTSTRAP_PASSWORD for non-interactive use.")
            password = getpass.getpass("Administrator password: ")
        if args.command == "reset-admin":
            reset_admin(engine, args.username, password)
            print("Administrator credential replaced; all sessions revoked.")
        else:
            if key is None:
                if not sys.stdin.isatty():
                    parser.error("Set GATEWAY_BOOTSTRAP_INTEGRATION_KEY for non-interactive use.")
                key = getpass.getpass("Integration bearer key (minimum 32 characters): ")
            bootstrap(engine, settings, args.username, password, key, args.external_subject)
            print("Installation bootstrapped.")
            if args.generate:
                print(f"Administrator password: {password}\nIntegration bearer key: {key}")
    except ValueError as error:
        # Pydantic configuration errors can carry input values. Show only our
        # own intentional operator messages, never a configuration traceback.
        if type(error) is not ValueError:
            parser.exit(1, "Installation configuration is invalid or incomplete.\n")
        parser.exit(1, f"{error}\n")
    except (SQLAlchemyError, PostgreSQLError, RuntimeError, OSError):
        parser.exit(1, "Database operation failed; verify installation configuration.\n")
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
