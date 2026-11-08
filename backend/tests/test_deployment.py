"""Operator tooling checks without a real provider, account or secret."""

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prepare_compose_is_private_idempotent_and_uses_distinct_secrets(tmp_path, monkeypatch, capsys):
    script = load_script("prepare-compose")
    monkeypatch.setattr(script, "ROOT", tmp_path)
    script.main()
    env = tmp_path / ".env.compose"
    access = json.loads((tmp_path / ".runtime/compose-access.json").read_text("utf-8"))
    original = env.read_bytes()
    script.main()
    assert env.read_bytes() == original
    values = [access[k] for k in ("csrf_secret", "identity_secret", "pseudonym_secret", "webui_secret")]
    assert len(set(values)) == 4 and all(len(value) >= 32 for value in values)
    assert not any(value in capsys.readouterr().out for value in values)
    if os.name != "nt":
        assert env.stat().st_mode & 0o077 == 0


def test_prepare_compose_refuses_unmatched_existing_config(tmp_path, monkeypatch):
    script = load_script("prepare-compose")
    monkeypatch.setattr(script, "ROOT", tmp_path)
    env = tmp_path / ".env.compose"
    env.write_text("operator-owned", encoding="utf-8")
    with pytest.raises(RuntimeError, match="matching credentials"):
        script.main()
    assert env.read_text("utf-8") == "operator-owned"


def test_live_connection_probe_requires_explicit_opt_in(monkeypatch):
    script = load_script("connect-openwebui")
    monkeypatch.setattr(script, "Settings", lambda: SimpleNamespace(demo_mode=False))
    with pytest.raises(RuntimeError, match="--verify-live"):
        script.internal("https://client.test")


def test_openwebui_model_is_configurable_and_text_only():
    script = load_script("connect-openwebui")
    calls = []

    class Client:
        def get(self, path, **kwargs):
            assert kwargs["params"]["id"] == "deepseek-flash"
            return SimpleNamespace(status_code=404)

        def post(self, path, **kwargs):
            calls.append(kwargs["json"])
            return SimpleNamespace(raise_for_status=lambda: None)

    script.authorize_model(Client(), {"token": "synthetic"}, {"id": "synthetic-user"}, "deepseek-flash", is_demo=False)
    assert calls[0]["id"] == "deepseek-flash"
    assert not any(calls[0]["meta"]["capabilities"].values())
    assert calls[0]["access_grants"][0]["principal_id"] == "synthetic-user"


def test_live_probe_accepts_initial_null_stream_delta_and_cleans_up_chat():
    script = load_script("connect-openwebui")
    deleted = []
    payloads = []

    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def execute(self, *_args):
            return SimpleNamespace(all=lambda: [("completed", "MASK"), ("completed", "MASK")])

        def raise_for_status(self):
            pass

        def iter_lines(self):
            yield 'data: {"choices":[{"delta":{"content":null}}]}'
            yield 'data: {"choices":[{"delta":{"content":"[EMAIL_SYNTHETIC]"},"finish_reason":"stop"}]}'
            yield 'data: [DONE]'

    class Client:
        def get(self, *_args, **_kwargs):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"data": [{"id": "deepseek-flash"}]})

        def post(self, path, **kwargs):
            payloads.append(kwargs["json"].copy())
            data = {"id": "synthetic-chat"} if path.endswith("/new") else {
                "choices": [{"message": {"role": "assistant", "content": "[EMAIL_SYNTHETIC]"}}]
            }
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: data)

        def stream(self, *_args, **_kwargs):
            return Context()

        def delete(self, path, **_kwargs):
            deleted.append(path)

    script.verify(Client(), {"token": "synthetic"}, SimpleNamespace(connect=Context), "deepseek-flash")
    assert deleted == ["/api/v1/chats/synthetic-chat"]
    assert all(p["max_tokens"] == 128 for p in payloads if "messages" in p)
