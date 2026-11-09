import re

import pytest
from gateway.detection import CATEGORIES, Detector, DetectorError, Finding, protect

SCOPE = {
    "integration_id": "11111111-1111-1111-1111-111111111111",
    "issuer": "open-webui",
    "sub": "overlap-test",
    "user_id": "22222222-2222-2222-2222-222222222222",
    "chat_id": "overlap-repro",
}
KEY = b"k" * 32


@pytest.fixture(scope="module")
def detector():
    return Detector()


@pytest.mark.parametrize("role", ["user", "assistant"])
def test_internal_domain_inside_email_is_masked_as_one_value(detector, role):
    messages = [
        {"role": role, "content": "Contact admin@db.internal"},
        {"role": "user", "content": "alice@example.com failed; retry alice@example.com"},
    ]
    findings = detector.analyze(messages, [])
    assert {f.category for f in findings if f.message_index == 0} == {"EMAIL", "INTERNAL_HOSTNAME"}
    result = protect(messages, findings, dict.fromkeys(CATEGORIES, "MASK"), SCOPE, KEY)
    assert result.decision == "MASK"
    assert re.fullmatch(r"Contact \[EMAIL_[A-Z2-7]{52}\]", result.messages[0]["content"])
    markers = re.findall(r"\[EMAIL_[A-Z2-7]{52}\]", result.messages[1]["content"])
    assert len(markers) == 2 and markers[0] == markers[1]
    assert result.counts == {"EMAIL": 3, "INTERNAL_HOSTNAME": 1}


@pytest.mark.parametrize("email_action", ["ALLOW", "MASK", "BLOCK"])
@pytest.mark.parametrize("host_action", ["ALLOW", "MASK", "BLOCK"])
def test_nested_categories_keep_their_policy_actions(detector, email_action, host_action):
    messages = [{"role": "user", "content": "Contact admin@db.internal"}]
    findings = detector.analyze(messages, [])
    actions = {**dict.fromkeys(CATEGORIES, "MASK"), "EMAIL": email_action, "INTERNAL_HOSTNAME": host_action}
    result = protect(messages, findings, actions, SCOPE, KEY)
    if "BLOCK" in {email_action, host_action}:
        assert result.decision == "BLOCK" and result.messages == []
    elif email_action == "MASK":
        assert re.fullmatch(r"Contact \[EMAIL_[A-Z2-7]{52}\]", result.messages[0]["content"])
    elif host_action == "MASK":
        assert re.fullmatch(r"Contact admin@\[INTERNAL_HOSTNAME_[A-Z2-7]{52}\]", result.messages[0]["content"])
    else:
        assert result.decision == "ALLOW" and result.messages == messages


@pytest.mark.parametrize("inner", [(0, 4), (2, 6), (2, 4)])
def test_containing_mask_covers_nested_ranges_with_shared_boundaries(inner):
    messages = [{"role": "user", "content": "abcdef"}]
    findings = [Finding(0, *inner, "PHONE", 1, "inner"), Finding(0, 0, 6, "EMAIL", 1, "outer")]
    result = protect(messages, findings, dict.fromkeys(CATEGORIES, "MASK"), SCOPE, KEY)
    assert re.fullmatch(r"\[EMAIL_[A-Z2-7]{52}\]", result.messages[0]["content"])


@pytest.mark.parametrize("second", [(2, 6), (0, 4)])
def test_crossing_or_identical_different_categories_remain_fail_closed(second):
    messages = [{"role": "user", "content": "abcdef"}]
    findings = [Finding(0, 0, 4, "EMAIL", 1, "a"), Finding(0, *second, "PHONE", 1, "b")]
    with pytest.raises(DetectorError, match="ambiguous_mask_overlap"):
        protect(messages, findings, dict.fromkeys(CATEGORIES, "MASK"), SCOPE, KEY)
