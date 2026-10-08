"""Create an isolated Windows PostgreSQL demo; credentials remain in git-ignored files."""

import json
import os
import secrets
import subprocess
from pathlib import Path
from urllib.parse import quote

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"


def run(*args):
    with (RUNTIME / "database-command.log").open("w", encoding="utf-8") as output:
        result = subprocess.run(
            [str(a) for a in args], stdout=output, stderr=subprocess.STDOUT, timeout=90, check=False
        )
    if result.returncode:
        raise RuntimeError(
            f"Local database command failed ({Path(str(args[0])).name}); inspect .runtime/postgres.log"
        )


def main():
    os.chdir(ROOT)
    RUNTIME.mkdir(exist_ok=True)
    access_path = RUNTIME / "access.json"
    if access_path.exists():
        access = json.loads(access_path.read_text("utf-8"))
    else:
        access = {
            key: secrets.token_urlsafe(36)
            for key in (
                "owner_password",
                "runtime_password",
                "admin_password",
                "integration_key",
                "csrf_secret",
                "pseudonym_secret",
                "identity_secret",
                "webui_secret",
            )
        }
        access.update(admin_username="admin", external_subject="demo-user", mode="demo")
        access_path.write_text(json.dumps(access, indent=2), encoding="utf-8")
    binaries = RUNTIME / "postgresql" / "pgsql" / "bin"
    data = RUNTIME / "pgdata"
    if not (data / "PG_VERSION").exists():
        pwfile = RUNTIME / "pg-initial-password"
        pwfile.write_text(access["owner_password"], encoding="utf-8")
        try:
            run(
                binaries / "initdb.exe",
                "-D",
                data,
                "-U",
                "gateway_owner",
                "--encoding=UTF8",
                "--locale=C",
                "--auth=scram-sha-256",
                "--pwfile",
                pwfile,
            )
        finally:
            pwfile.unlink(missing_ok=True)
        with (data / "postgresql.conf").open("a", encoding="utf-8") as out:
            out.write(
                "\nlisten_addresses = '127.0.0.1'\nport = 55432\nlog_statement = 'none'\nlog_min_error_statement = 'panic'\n"
            )
    status = subprocess.run(
        [str(binaries / "pg_ctl.exe"), "-D", str(data), "status"], capture_output=True, check=False
    )
    if status.returncode:
        run(binaries / "pg_ctl.exe", "-D", data, "-l", RUNTIME / "postgres.log", "-w", "start")
    owner_url = f"postgresql://gateway_owner:{quote(access['owner_password'])}@127.0.0.1:55432/gateway"
    with psycopg.connect(
        host="127.0.0.1",
        port=55432,
        user="gateway_owner",
        password=access["owner_password"],
        dbname="postgres",
        autocommit=True,
    ) as conn:
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname='gateway'").fetchone():
            conn.execute("CREATE DATABASE gateway")
    env = {
        "GATEWAY_DATABASE_URL": f"postgresql+psycopg://gateway_runtime:{quote(access['runtime_password'])}@127.0.0.1:55432/gateway",
        "GATEWAY_MIGRATION_DATABASE_URL": owner_url.replace("postgresql://", "postgresql+psycopg://"),
        "GATEWAY_PUBLIC_ORIGIN": "http://localhost:8000",
        "GATEWAY_DEMO_MODE": "true",
        "GATEWAY_CSRF_SECRET": access["csrf_secret"],
        "GATEWAY_PSEUDONYM_SECRET": access["pseudonym_secret"],
        "GATEWAY_IDENTITY_SECRET": access["identity_secret"],
        "GATEWAY_PROVIDER_ALLOWED_HOSTS": "api.openai.com",
        "GATEWAY_PROVIDER_SECRET": "",
        "GATEWAY_PROVIDER_SECRET_REF": "provider-default",
    }
    env_path = ROOT / ".env"
    if not env_path.exists():
        env_path.write_text("\n".join(f"{k}={v}" for k, v in env.items()) + "\n", encoding="utf-8")
    (RUNTIME / "test.env").write_text(
        "GATEWAY_TEST_DATABASE_URL=" + env["GATEWAY_MIGRATION_DATABASE_URL"] + "\n", encoding="utf-8"
    )
    from gateway.db import bootstrap, make_engine, migrate
    from gateway.settings import Settings
    from sqlalchemy import text

    config = Settings(**{key.removeprefix("GATEWAY_").lower(): value for key, value in env.items()})
    owner = make_engine(config.model_copy(update={"database_url": env["GATEWAY_MIGRATION_DATABASE_URL"]}))
    migrate(owner)
    with owner.connect() as conn:
        exists = conn.execute(text("SELECT EXISTS(SELECT 1 FROM users)")).scalar()
    if not exists:
        access["ids"] = bootstrap(owner, config, "admin", access["admin_password"], access["integration_key"])
        access_path.write_text(json.dumps(access, indent=2), encoding="utf-8")
    with psycopg.connect(owner_url) as conn:
        conn.execute(
            (ROOT / "backend" / "migrations" / "provision_roles.sql").read_text("utf-8"), prepare=False
        )
        conn.execute(
            sql.SQL("ALTER ROLE gateway_runtime PASSWORD {}").format(sql.Literal(access["runtime_password"]))
        )
    owner.dispose()
    print(
        "Local PostgreSQL initialized. Admin access: .runtime/access.json. Start with scripts/start-local.ps1."
    )


if __name__ == "__main__":
    main()
