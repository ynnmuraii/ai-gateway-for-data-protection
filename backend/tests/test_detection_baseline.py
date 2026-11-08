import base64
import json

import pytest
from gateway.detection import Detector, DetectorError


def jwt():
    encode = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=")
    return encode({"alg": "HS256", "typ": "JWT"}) + "." + encode({"sub": "user"}) + "." + "a" * 43


@pytest.fixture(scope="module")
def detector():
    return Detector()


@pytest.mark.parametrize("language", ["Contact", "Контакт"])
def test_seven_category_corpus_exact_python_offsets(detector, language):
    samples = {
        "EMAIL": "person@example.com",
        "PHONE": "+7 (912) 345-67-89",
        "IP_ADDRESS": "10.20.30.40",
        "INTERNAL_HOSTNAME": "db.prod.internal",
        "API_KEY": "AKIA" + "A" * 16,
        "ACCESS_TOKEN": "ghp_" + "a" * 36,
        "JWT": jwt(),
    }
    text = language + " 😀 " + " ; ".join(samples.values())
    found = detector.analyze([{"role": "user", "content": text}], [])
    for category, value in samples.items():
        assert any(f.category == category and text[f.start : f.end] == value for f in found), (
            category,
            found,
        )
    assert len(found) == len({(f.message_index, f.start, f.end, f.category) for f in found})


def test_private_ip_public_ip_invalid_and_host_boundaries(detector):
    text = "10.0.0.1 8.8.8.8 999.2.3.4 fd00::1 2001:4860:4860::8888 db.internal db.internal.evil"
    found = detector.analyze([{"role": "user", "content": text}], [])
    ip_values = {text[f.start : f.end] for f in found if f.category == "IP_ADDRESS"}
    assert ip_values == {"10.0.0.1", "fd00::1"}
    assert {text[f.start : f.end] for f in found if f.category == "INTERNAL_HOSTNAME"} == {"db.internal"}


def test_dictionary_schema_exact_and_unicode_case_insensitive_offsets(detector):
    text = "xСЕКРЕТx; СЕКРЕТ; Straße; STRASSE; svc.example.com.evil svc.example.com"
    rows = [
        {"category": "API_KEY", "entry_value": "СЕКРЕТ"},
        {"category": "API_KEY", "value": "Straße", "match_mode": "case_insensitive"},
        {"category": "INTERNAL_HOSTNAME", "entry_value": "svc.example.com"},
    ]
    found = detector.analyze([{"role": "user", "content": text}], rows)
    assert {text[f.start : f.end] for f in found if f.recognizer_id.startswith("dictionary")} == {
        "СЕКРЕТ",
        "Straße",
        "svc.example.com",
    }


def test_no_entropy_guess_malformed_jwt_or_ordinary_assignment(detector):
    text = (
        "id=abcdefghijklmnopqrstuvwxyz0123456789 token=x jwt=eyJhbGciOiJIUzI1NiJ9.bad.bad email=not-an-email"
    )
    assert detector.analyze([{"role": "user", "content": text}], []) == []


def test_missing_models_fails_readiness_without_download(monkeypatch):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    with pytest.raises(DetectorError, match="detector_models_missing"):
        Detector()


def test_ip_inside_technical_port_and_sentence_punctuation(detector):
    text = "Connect 10.0.0.1:5432, then fd00::1. End 192.168.2.3."
    found = detector.analyze([{"role": "user", "content": text}], [])
    assert {text[f.start : f.end] for f in found if f.category == "IP_ADDRESS"} == {
        "10.0.0.1",
        "fd00::1",
        "192.168.2.3",
    }


@pytest.mark.parametrize(
    ("text", "value", "category"),
    [
        (
            "status=failed; address=dev_10102@team10102.example.com; retry=false",
            "dev_10102@team10102.example.com",
            "EMAIL",
        ),
        ("email=a=b@example.com", "a=b@example.com", "EMAIL"),
        ("Contact a=b@example.com", "a=b@example.com", "EMAIL"),
        ("Contact user+tag=alias@example.com", "user+tag=alias@example.com", "EMAIL"),
        ("[+44 20 7946 0003]", "+44 20 7946 0003", "PHONE"),
        ("(+12025550123)", "+12025550123", "PHONE"),
        ("Contact (202) 555-0123", "(202) 555-0123", "PHONE"),
        ("Contact +7 (912) 345-67-89", "+7 (912) 345-67-89", "PHONE"),
    ],
)
def test_field_delimiters_and_outer_wrappers_do_not_expand_sensitive_span(detector, text, value, category):
    found = detector.analyze([{"role": "user", "content": text}], [])
    assert {text[f.start : f.end] for f in found if f.category == category} == {value}
