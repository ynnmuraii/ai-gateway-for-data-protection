"""Provision Open WebUI locally, map its real subject, and verify its chat path."""

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

import httpx
from gateway.db import make_engine
from gateway.settings import Settings
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

ROOT = Path(__file__).resolve().parents[1]
TEXT_CAPABILITIES = {
    "vision": False,
    "file_upload": False,
    "web_search": False,
    "code_interpreter": False,
    "image_generation": False,
    "builtin_tools": False,
    "terminal": False,
}


def session(client, email, password):
    response = client.post("/api/v1/auths/signin", json={"email": email, "password": password})
    return response.json() if response.is_success else None


def internal(url, *, verify_live=False):
    settings = Settings()
    if not settings.demo_mode and not verify_live:
        raise RuntimeError("Real-provider acceptance requires --verify-live (three small synthetic requests).")
    # Only this installation job can access the blocked first-user signup route.
    with httpx.Client(base_url=url, timeout=120, trust_env=False) as client:
        admin = session(client, os.environ["WEBUI_ADMIN_EMAIL"], os.environ["WEBUI_ADMIN_PASSWORD"])
        if admin is None:
            response = client.post(
                "/api/v1/auths/signup",
                json={
                    "email": os.environ["WEBUI_ADMIN_EMAIL"],
                    "password": os.environ["WEBUI_ADMIN_PASSWORD"],
                    "name": "Local operator",
                },
            )
            response.raise_for_status()
            admin = response.json()
        if admin.get("role") != "admin":
            raise RuntimeError("Operator account is not an administrator.")
        user = session(client, os.environ["WEBUI_USER_EMAIL"], os.environ["WEBUI_USER_PASSWORD"])
        if user is None:
            response = client.post(
                "/api/v1/auths/add",
                headers={"Authorization": "Bearer " + admin["token"]},
                json={
                    "email": os.environ["WEBUI_USER_EMAIL"],
                    "password": os.environ["WEBUI_USER_PASSWORD"],
                    "name": "Gateway demo user",
                    "role": "user",
                },
            )
            response.raise_for_status()
            user = response.json()
        if user.get("role") != "user" or not user.get("id"):
            raise RuntimeError("Demo account is not a regular verified user.")
        engine = make_engine(
            settings.model_copy(update={"database_url": os.environ["GATEWAY_INSTALL_DATABASE_URL"]})
        )
        try:
            with engine.begin() as connection:
                provider = connection.execute(text("SELECT base_url,allowed_models FROM provider_config")).mappings().one()
                is_demo = provider["base_url"].rstrip("/") == "https://demo.invalid/v1"
                if not is_demo and not verify_live:
                    raise RuntimeError("Real-provider acceptance requires --verify-live.")
                model_id = provider["allowed_models"][0]
                key_hash = hashlib.sha256(os.environ["GATEWAY_BOOTSTRAP_INTEGRATION_KEY"].encode()).digest()
                integration = connection.execute(
                    text("SELECT id FROM client_integrations WHERE bearer_key_hash=:hash AND enabled"),
                    {"hash": key_hash},
                ).scalar_one()
                local_user = connection.execute(
                    text("SELECT id FROM users WHERE username='demo-user' AND role='user' AND enabled")
                ).scalar_one()
                existing = (
                    connection.execute(
                        text(
                            "SELECT id,user_id,revoked_at FROM external_identities "
                            "WHERE integration_id=:integration AND external_subject=:subject"
                        ),
                        {"integration": integration, "subject": user["id"]},
                    )
                    .mappings()
                    .first()
                )
                if existing:
                    if existing["user_id"] != local_user or existing["revoked_at"] is not None:
                        raise RuntimeError(
                            "Existing subject mapping is incompatible or revoked; operator review required."
                        )
                else:
                    connection.execute(
                        text(
                            "INSERT INTO external_identities (id,integration_id,user_id,external_subject) "
                            "VALUES (:id,:integration,:user,:subject)"
                        ),
                        {
                            "id": uuid.uuid4(),
                            "integration": integration,
                            "user": local_user,
                            "subject": user["id"],
                        },
                    )
                connection.execute(
                    text(
                        "UPDATE external_identities SET revoked_at=now() "
                        "WHERE integration_id=:integration AND external_subject='compose-unmapped' "
                        "AND revoked_at IS NULL"
                    ),
                    {"integration": integration},
                )
            authorize_model(client, admin, user, model_id, is_demo=is_demo)
            verify(client, user, engine, model_id)
        finally:
            engine.dispose()
    print(
        "Open WebUI regular user authorized; model listing, masked chat, SSE and assistant-history follow-up verified through the gateway."
    )


def authorize_model(client, admin, user, model_id="demo-model", *, is_demo=True):
    headers = {"Authorization": "Bearer " + admin["token"]}
    grant = {"principal_type": "user", "principal_id": user["id"], "permission": "read"}
    response = client.get("/api/v1/models/model", params={"id": model_id}, headers=headers)
    if response.status_code == 404 or (response.is_success and response.json() is None):
        response = client.post(
            "/api/v1/models/create",
            headers=headers,
            json={
                "id": model_id,
                "name": "Gateway simulator (no LLM)" if is_demo else "Gateway: " + model_id,
                "params": {},
                "meta": {"capabilities": TEXT_CAPABILITIES},
                "access_grants": [grant],
            },
        )
        response.raise_for_status()
    else:
        response.raise_for_status()
        model = response.json()
        if not any(
            all(entry.get(key) == value for key, value in grant.items())
            for entry in model.get("access_grants", [])
        ):
            raise RuntimeError(
                "Existing Open WebUI model does not authorize the demo user; review its grants."
            )
        meta = model.get("meta") or {}
        capabilities = meta.get("capabilities") or {}
        if any(capabilities.get(key) is not value for key, value in TEXT_CAPABILITIES.items()):
            # This installation owns the demo model. Reconcile its strict text
            # capabilities without changing accounts, access grants or parameters.
            meta = {**meta, "capabilities": {**capabilities, **TEXT_CAPABILITIES}}
            response = client.post(
                "/api/v1/models/model/update",
                params={"id": model_id},
                headers=headers,
                json={
                    "id": model["id"],
                    "base_model_id": model.get("base_model_id"),
                    "name": model["name"],
                    "meta": meta,
                    "params": model.get("params") or {},
                    "access_grants": model.get("access_grants"),
                    "is_active": model.get("is_active", True),
                },
            )
            response.raise_for_status()


def verify(client, user, engine, model_id="demo-model"):
    headers = {"Authorization": "Bearer " + user["token"]}
    response = client.get("/api/models", headers=headers)
    response.raise_for_status()
    if model_id not in {item["id"] for item in response.json()["data"]}:
        raise RuntimeError("Expected demo model was not listed.")
    response = client.post(
        "/api/v1/chats/new",
        headers=headers,
        json={
            "chat": {
                "title": "Gateway verification",
                "models": [model_id],
                "messages": [],
                "history": {"messages": {}, "currentId": None},
            }
        },
    )
    response.raise_for_status()
    chat_id = response.json()["id"]
    sample = "Repeat only the contact marker from this text: integration@example.com. Do not invent an address."
    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": sample}],
        "chat_id": chat_id,
        "stream": False,
        "max_tokens": 128,
    }
    try:
        response = client.post("/api/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        output = response.json()["choices"][0]["message"]["content"]
        if "integration@example.com" in output:
            raise RuntimeError("Gateway did not mask the verification sample.")
        payload["stream"] = True
        pieces = []
        complete = False
        with client.stream("POST", "/api/chat/completions", headers=headers, json=payload) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                frame = line[6:]
                if frame == "[DONE]":
                    complete = True
                    continue
                data = json.loads(frame)
                if "error" in data:
                    raise RuntimeError("Streaming verification returned an error.")
                for choice in data.get("choices", []):
                    pieces.append(choice.get("delta", {}).get("content", ""))
                    if choice.get("finish_reason") == "stop":
                        complete = True
        streamed = "".join(pieces)
        if not complete or "integration@example.com" in streamed:
            raise RuntimeError("Masked streaming completion was not verified.")
        with engine.connect() as connection:
            states = connection.execute(
                text("SELECT state,decision FROM audit_events ORDER BY occurred_at DESC LIMIT 2")
            ).all()
        if len(states) != 2 or any(state != "completed" or decision != "MASK" for state, decision in states):
            raise RuntimeError("Chat completion audit outcomes were not verified.")
        # A real GUI replays the raw user message and the assistant's masked
        # answer on its next turn. The assistant marker must remain ordinary
        # scanned history, without authorizing unscanned user/system literals.
        payload["stream"] = False
        payload["messages"] = [
            {"role": "user", "content": sample},
            {"role": "assistant", "content": output},
            {"role": "user", "content": "Continue with a short explanation."},
        ]
        response = client.post("/api/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        if "choices" not in response.json():
            raise RuntimeError("Masked assistant history follow-up was not verified.")
    finally:
        # Do not leave the helper's transient sample in the client's chat store.
        client.delete("/api/v1/chats/" + chat_id, headers=headers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--url", default="http://openwebui:8080")
    parser.add_argument("--verify-live", action="store_true", help="Allow three short synthetic requests to the configured paid provider.")
    args = parser.parse_args()
    if args.internal:
        internal(args.url, verify_live=args.verify_live)
    else:
        command = [
                "docker",
                "compose",
                "--env-file",
                ".env.compose",
                "--profile",
                "tools",
                "run",
                "--rm",
                "connect-openwebui",
            ]
        if args.verify_live:
            command += ["python", "scripts/connect-openwebui.py", "--internal", "--verify-live"]
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
        )
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except httpx.HTTPStatusError as error:
        raise SystemExit(
            f"Open WebUI operation failed with HTTP {error.response.status_code} "
            f"at {error.request.url.path}. No credentials or response body were logged."
        ) from None
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError, httpx.RequestError, SQLAlchemyError):
        raise SystemExit(
            "Open WebUI connection or verification failed; inspect service health and local configuration. "
            "No token, password or prompt was logged."
        ) from None
