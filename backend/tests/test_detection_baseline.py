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
def test_two_category_corpus_exact_python_offsets(detector, language):
    samples = {"EMAIL": "person@example.com", "JWT": jwt()}
    text = language + " 😀 " + " ; ".join(samples.values())
    found = detector.analyze([{"role": "user", "content": text}], [])
    for category, value in samples.items():
        assert any(f.category == category and text[f.start : f.end] == value for f in found), (
            category,
            found,
        )
    assert len(found) == len({(f.message_index, f.start, f.end, f.category) for f in found})






def test_no_entropy_guess_malformed_jwt_or_ordinary_assignment(detector):
    text = (
        "id=abcdefghijklmnopqrstuvwxyz0123456789 token=x jwt=eyJhbGciOiJIUzI1NiJ9.bad.bad email=not-an-email"
    )
    assert detector.analyze([{"role": "user", "content": text}], []) == []


def test_missing_models_fails_readiness_without_download(monkeypatch):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    with pytest.raises(DetectorError, match="detector_models_missing"):
        Detector()


