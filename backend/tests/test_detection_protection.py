import base64
import hashlib
import hmac
import re

import pytest
from gateway.detection import CATEGORIES, DetectorError, Finding, frame, protect

SCOPE = {
    "integration_id": "11111111-1111-1111-1111-111111111111",
    "issuer": "open-webui",
    "sub": "юзер",
    "user_id": "22222222-2222-2222-2222-222222222222",
    "chat_id": "chat-1",
}
KEY = b"k" * 32
ACTIONS = dict.fromkeys(CATEGORIES, "MASK")


def finding(text, value, category="EMAIL", message_index=0):
    start = text.index(value)
    return Finding(message_index, start, start + len(value), category, 1.0, "test")


def test_framing_unicode_empty_boundaries_and_maximum():
    assert frame([b"ab", b"c"]) != frame([b"a", b"bc"])
    assert frame(["ю".encode(), b""]) == b"\x00\x00\x00\x02\xd1\x8e\x00\x00\x00\x00"
    assert frame([b"a" * 262144])[:4] == b"\x00\x04\x00\x00"


def test_exact_stable_hmac_vector_original_segments_and_scope():
    text = "Привет: person@example.com; again person@example.com!"
    f = finding(text, "person@example.com")
    duplicate = Finding(0, text.rindex("person"), text.rindex("person") + 18, "EMAIL", 1, "test")
    result = protect([{"role": "user", "content": text}], [f, f, duplicate], ACTIONS, SCOPE, KEY)
    fields = [
        "gateway-pseudonym-v1",
        SCOPE["integration_id"],
        "open-webui",
        "юзер",
        SCOPE["user_id"],
        "chat-1",
        "EMAIL",
        "person@example.com",
    ]
    digest = base64.b32encode(hmac.new(KEY, frame([v.encode() for v in fields]), hashlib.sha256).digest())
    marker = "[EMAIL_" + digest.decode().rstrip("=") + "]"
    assert re.fullmatch(r"\[EMAIL_[A-Z2-7]{52}\]", marker)
    assert result.messages[0]["content"] == "Привет: " + marker + "; again " + marker + "!"
    assert result.counts == {"EMAIL": 2}
    assert result.decision == "MASK"
    assert (
        protect(
            [{"role": "user", "content": text}], [f], ACTIONS, {**SCOPE, "chat_id": "chat-2"}, KEY
        ).messages
        != result.messages
    )


def test_block_precedes_ambiguous_mask_and_contains_no_raw_messages():
    text = "abcdef"
    fs = [
        Finding(0, 0, 4, "EMAIL", 1, "a"),
        Finding(0, 2, 6, "PHONE", 1, "b"),
        Finding(0, 0, 6, "API_KEY", 1, "c"),
    ]
    result = protect([{"role": "user", "content": text}], fs, {**ACTIONS, "API_KEY": "BLOCK"}, SCOPE, KEY)
    assert result.decision == "BLOCK" and result.messages == []


def test_overlap_unknown_policy_and_bad_offsets_fail_closed():
    messages = [{"role": "user", "content": "abcdef"}]
    with pytest.raises(DetectorError, match="ambiguous_mask_overlap"):
        protect(
            messages,
            [Finding(0, 0, 4, "EMAIL", 1, "a"), Finding(0, 2, 6, "PHONE", 1, "b")],
            ACTIONS,
            SCOPE,
            KEY,
        )
    with pytest.raises(DetectorError):
        protect(messages, [Finding(0, -1, 4, "EMAIL", 1, "a")], ACTIONS, SCOPE, KEY)
    with pytest.raises(DetectorError):
        protect(messages, [], {}, SCOPE, KEY)


def test_literal_marker_and_computed_collision(monkeypatch):
    source = "a@b.com"
    marker = protect(
        [{"role": "user", "content": source}], [finding(source, source)], ACTIONS, SCOPE, KEY
    ).messages[0]["content"]
    text = source + " " + marker
    with pytest.raises(DetectorError, match="literal_marker_conflict"):
        protect([{"role": "user", "content": text}], [finding(text, "a@b.com")], ACTIONS, SCOPE, KEY)
    monkeypatch.setattr("gateway.detection.protection.marker_for", lambda *a: "[EMAIL_" + "A" * 52 + "]")
    text = "a@b.com c@d.com"
    with pytest.raises(DetectorError, match="pseudonym_collision"):
        protect(
            [{"role": "user", "content": text}],
            [finding(text, "a@b.com"), finding(text, "c@d.com")],
            ACTIONS,
            SCOPE,
            KEY,
        )


def test_exact_unicode_values_do_not_normalize_and_allow_preserves_shape():
    messages = [{"role": "system", "content": "café café"}]
    fs = [Finding(0, 0, 4, "INTERNAL_HOSTNAME", 1, "a"), Finding(0, 5, 10, "INTERNAL_HOSTNAME", 1, "a")]
    result = protect(messages, fs, ACTIONS, SCOPE, KEY)
    assert result.messages[0]["content"].split()[0] != result.messages[0]["content"].split()[1]
    allowed = protect(messages, fs, dict.fromkeys(CATEGORIES, "ALLOW"), SCOPE, KEY)
    assert allowed.decision == "ALLOW" and allowed.messages == messages


def test_prior_different_marker_remains_literal_while_new_secret_is_masked():
    literal = "[EMAIL_" + "A" * 52 + "]"
    text = "a@b.com " + literal
    result = protect([{"role": "user", "content": text}], [finding(text, "a@b.com")], ACTIONS, SCOPE, KEY)
    assert result.decision == "MASK"
    assert result.messages[0]["content"].endswith(" " + literal)
    assert not result.messages[0]["content"].startswith("a@b.com")
