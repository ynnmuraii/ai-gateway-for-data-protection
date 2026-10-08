"""Generate ignored local deployment secrets without displaying their values."""

import json
import os
import secrets
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def private_write(path: Path, source: str):
    with path.open("x", encoding="utf-8", newline="\n") as out:
        out.write(source)
    if os.name != "nt":
        path.chmod(0o600)


def main():
    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)
    destination = ROOT / ".env.compose"
    access_path = runtime / "compose-access.json"
    if destination.exists():
        if not access_path.exists():
            raise RuntimeError("Existing .env.compose has no matching credentials file; restore its backup.")
        print("Existing Compose configuration retained. Credentials: .runtime/compose-access.json")
        return
    if access_path.exists():
        access = json.loads(access_path.read_text("utf-8"))
    else:
        local = runtime / "access.json"
        access = json.loads(local.read_text("utf-8")) if local.exists() else {}
        for key in (
            "owner_password",
            "runtime_password",
            "admin_password",
            "integration_key",
            "csrf_secret",
            "pseudonym_secret",
            "identity_secret",
            "webui_secret",
            "webui_admin_password",
            "webui_user_password",
        ):
            access.setdefault(key, secrets.token_urlsafe(36))
        access.setdefault("admin_username", "admin")
        access.setdefault("webui_admin_email", "operator@example.com")
        access.setdefault("webui_user_email", "demo@example.com")
        if (
            len(
                {
                    access[key]
                    for key in ("csrf_secret", "pseudonym_secret", "identity_secret", "webui_secret")
                }
            )
            != 4
        ):
            raise RuntimeError("Deployment secrets must be distinct.")
        private_write(access_path, json.dumps(access, indent=2) + "\n")
    environment = {
        "COMPOSE_PROJECT_NAME": "confidential-ai-gateway",
        "POSTGRES_PASSWORD": access["owner_password"],
        "GATEWAY_RUNTIME_PASSWORD": access["runtime_password"],
        "GATEWAY_INSTALL_DATABASE_URL": "postgresql+psycopg://gateway_owner:"
        + quote(access["owner_password"], safe="")
        + "@postgres:5432/gateway",
        "GATEWAY_DATABASE_URL": "postgresql+psycopg://gateway_runtime:"
        + quote(access["runtime_password"], safe="")
        + "@postgres:5432/gateway",
        "GATEWAY_PUBLIC_ORIGIN": "http://localhost:8080",
        "GATEWAY_DEMO_MODE": "true",
        "GATEWAY_PROVIDER_ALLOWED_HOSTS": "api.openai.com",
        "GATEWAY_PROVIDER_SECRET": "",
        "GATEWAY_PROVIDER_SECRET_REF": "provider-default",
        "GATEWAY_CSRF_SECRET": access["csrf_secret"],
        "GATEWAY_PSEUDONYM_SECRET": access["pseudonym_secret"],
        "GATEWAY_IDENTITY_SECRET": access["identity_secret"],
        "GATEWAY_BOOTSTRAP_USERNAME": access["admin_username"],
        "GATEWAY_BOOTSTRAP_PASSWORD": access["admin_password"],
        "GATEWAY_BOOTSTRAP_INTEGRATION_KEY": access["integration_key"],
        "WEBUI_SECRET_KEY": access["webui_secret"],
        "WEBUI_ADMIN_EMAIL": access["webui_admin_email"],
        "WEBUI_ADMIN_PASSWORD": access["webui_admin_password"],
        "WEBUI_USER_EMAIL": access["webui_user_email"],
        "WEBUI_USER_PASSWORD": access["webui_user_password"],
    }
    if any("\n" in value or "\r" in value or "'" in value for value in environment.values()):
        raise RuntimeError("A configuration value cannot be encoded safely.")
    private_write(
        destination,
        "# Private local configuration; never commit or print.\n"
        + "\n".join(f"{name}='{value}'" for name, value in environment.items())
        + "\n",
    )
    print("Compose configuration prepared. Credentials: .runtime/compose-access.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        raise SystemExit(
            "Compose preparation failed; verify the ignored local configuration files."
        ) from None
