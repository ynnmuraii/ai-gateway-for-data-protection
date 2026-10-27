import base64
import hashlib
import importlib.metadata
import importlib.util
import ipaddress
import json
import re

from .types import CATEGORIES, DetectorError, Finding, validate_messages

LANGUAGES = {"ru": "ru_core_news_sm", "en": "en_core_web_sm"}
NLP_EXCLUDED_PIPES = ("tok2vec", "tagger", "morphologizer", "parser", "attribute_ruler", "lemmatizer", "ner", "senter")
PRIVATE_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)
HOST_SUFFIXES = (".internal", ".corp", ".local")
IP_CANDIDATE = re.compile(
    r"(?<![\w.:])(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-fA-F0-9]*:[a-fA-F0-9:.]+)(?![\w]|\.\w)"
)
HOST_CANDIDATE = re.compile(
    r"(?<![\w.-])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w.-])"
)
SIGNATURES = (
    ("API_KEY", "aws-access-key-v1", r"(?<![\w])(?:AKIA|ASIA)[A-Z0-9]{16}(?![\w])"),
    ("API_KEY", "openai-key-v1", r"(?<![\w-])sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,200}(?![\w-])"),
    (
        "ACCESS_TOKEN",
        "github-token-v1",
        r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,255})(?![\w])",
    ),
    (
        "ACCESS_TOKEN",
        "slack-token-v1",
        r"(?<![\w-])xox[baprs]-[0-9]{8,16}-[0-9]{8,16}-[A-Za-z0-9]{16,64}(?![\w-])",
    ),
)
COMPILED_SIGNATURES = [
    (category, recognizer, re.compile(pattern)) for category, recognizer, pattern in SIGNATURES
]
JWT_CANDIDATE = re.compile(
    r"(?<![\w.-])[A-Za-z0-9_-]{2,2731}\.[A-Za-z0-9_-]{2,21846}\.[A-Za-z0-9_-]{2,2731}(?![\w.-])"
)
TOKEN_ASSIGNMENT = re.compile(
    r"(?:\bauthorization\s*:\s*bearer\s+|\b(?:access[_-]?token|token)\s*[:=]\s*[\"']?)([A-Za-z0-9._~+/-]{16,2048}=*)",
    re.IGNORECASE,
)
EMAIL_FIELD_PREFIX = re.compile(r"(?:e-?mail(?:_address)?|address)=", re.IGNORECASE)


def profile_manifest(cidrs=PRIVATE_CIDRS, hostname_suffixes=HOST_SUFFIXES):
    packages = {}
    for name in ("presidio-analyzer", "phonenumbers", "spacy", *LANGUAGES.values()):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "missing"
    return {
        "schema": "gateway-detector-v1",
        "enabled_categories": list(CATEGORIES),
        "packages": packages,
        "languages": LANGUAGES,
        "nlp_pipeline": {"mode": "tokenizer-only", "excluded": NLP_EXCLUDED_PIPES},
        "regions": ["RU", "US", "GB"],
        "cidrs": list(cidrs),
        "hostname_suffixes": list(hostname_suffixes),
        "signatures": SIGNATURES,
        "patterns": {
            "ip": IP_CANDIDATE.pattern,
            "hostname": HOST_CANDIDATE.pattern,
            "jwt": JWT_CANDIDATE.pattern,
            "assigned_token": TOKEN_ASSIGNMENT.pattern,
        },
        "thresholds": {"email-local-v1": 0.5, "phone-v1": 0.4},
        "coordinates": "original-python-unicode-half-open-v1",
        "validators": "local-format-v1",
        "span_normalization": {"email_field_prefix": EMAIL_FIELD_PREFIX.pattern, "phone_wrappers": "unbalanced-v1"},
        "dictionary": "exact-or-explicit-ignorecase-unicode-boundaries-v1",
    }


def profile_checksum(cidrs=PRIVATE_CIDRS, hostname_suffixes=HOST_SUFFIXES):
    data = json.dumps(profile_manifest(cidrs, hostname_suffixes), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


def sprint1_profile_checksum():
    return previous_profile_checksums()["sprint1"]


def previous_profile_checksums():
    """Only reviewed saved bundles qualify; model/package version drift still needs review."""
    manifest = profile_manifest()
    manifest.pop("span_normalization")
    manifest.pop("nlp_pipeline")
    checksums = {}
    for name, categories in (("sprint1", ["EMAIL", "JWT"]), ("prototype", None),
                             ("sprint2-initial", list(CATEGORIES))):
        previous = manifest.copy()
        if categories is None:
            previous.pop("enabled_categories")
        else:
            previous["enabled_categories"] = categories
        data = json.dumps(previous, sort_keys=True, separators=(",", ":"))
        checksums[name] = hashlib.sha256(data.encode()).hexdigest()
    return checksums


def _valid_jwt(value):
    try:
        decoded = []
        for part, bound in zip(value.split("."), (2048, 16384, 2048)):
            payload = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            if len(payload) > bound:
                return False
            decoded.append(payload)
        header, claims = json.loads(decoded[0]), json.loads(decoded[1])
        return (
            isinstance(header, dict)
            and isinstance(header.get("alg"), str)
            and 1 <= len(header["alg"]) <= 64
            and isinstance(claims, dict)
            and bool(decoded[2])
        )
    except (ValueError, UnicodeError, IndexError, RecursionError):
        return False


def _boundary(text, start, end, hostname=False):
    extra = ".-" if hostname else ""
    return (
        start == 0 or not (text[start - 1].isalnum() or text[start - 1] == "_" or text[start - 1] in extra)
    ) and (end == len(text) or not (text[end].isalnum() or text[end] == "_" or text[end] in extra))


def _recognizer_span(text, start, end, category):
    if category == "EMAIL":
        # Known log field labels are context; '=' and '+' elsewhere remain valid local-part characters.
        candidate = text[start:end]
        prefix = EMAIL_FIELD_PREFIX.match(candidate)
        if prefix and prefix.end() < candidate.rfind("@"):
            start += prefix.end()
    elif category == "PHONE":
        while start < end and text[start] == "[":
            start += 1
        while start < end and text[start] == "(" and text[start:end].count("(") > text[start:end].count(")"):
            start += 1
    return start, end


class Detector:
    """Immutable local RU/EN Presidio engine plus deterministic format recognizers."""

    def __init__(self, *, protected_cidrs=PRIVATE_CIDRS, hostname_suffixes=HOST_SUFFIXES):
        if any(importlib.util.find_spec(model) is None for model in LANGUAGES.values()):
            raise DetectorError("detector_models_missing")
        try:
            import phonenumbers
            import spacy
            from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
            from presidio_analyzer.nlp_engine import SpacyNlpEngine
            from presidio_analyzer.predefined_recognizers import EmailRecognizer, PhoneRecognizer

            class LocalEmailRecognizer(EmailRecognizer):
                # Presidio's default validator uses tldextract, which may download/cache a PSL.
                def validate_result(self, pattern_text):
                    local, domain = pattern_text.rsplit("@", 1)
                    return (
                        0 < len(local) <= 64
                        and not local.startswith(".")
                        and ".." not in local
                        and len(domain) <= 253
                        and all(0 < len(label) <= 63 for label in domain.split("."))
                    )

            engine = SpacyNlpEngine(
                models=[{"lang_code": lang, "model_name": name} for lang, name in LANGUAGES.items()]
            )
            # Load installed packages directly; never call SpacyNlpEngine.load(), which downloads missing weights.
            # These recognizers use regex/phone parsing; NER, tagging and parsing add no findings.
            engine.nlp = {lang: spacy.load(name, exclude=NLP_EXCLUDED_PIPES) for lang, name in LANGUAGES.items()}
            registry = RecognizerRegistry(supported_languages=list(LANGUAGES))
            for lang in LANGUAGES:
                registry.add_recognizer(
                    LocalEmailRecognizer(
                        supported_language=lang, supported_entity="EMAIL", name="email-local-v1"
                    )
                )
                registry.add_recognizer(
                    PhoneRecognizer(
                        supported_language=lang,
                        supported_entity="PHONE",
                        supported_regions=("RU", "US", "GB"),
                        name="phone-v1",
                    )
                )
            self.engine = AnalyzerEngine(
                registry=registry,
                nlp_engine=engine,
                supported_languages=list(LANGUAGES),
                log_decision_process=False,
            )
            # Metadata imports read installed files; complete these before handling any original input.
            phonenumbers.PhoneMetadata.load_all()
            self.networks = tuple(ipaddress.ip_network(cidr) for cidr in protected_cidrs)
            self.suffixes = tuple(suffix.lower() for suffix in hostname_suffixes)
            if any(not re.fullmatch(r"\.[a-z0-9.-]+", suffix) for suffix in self.suffixes):
                raise ValueError
            self.checksum = profile_checksum(protected_cidrs, hostname_suffixes)
        except Exception:  # noqa: BLE001 - third-party model errors must not expose sensitive diagnostics
            raise DetectorError("detector_initialization_failed") from None

    def analyze(self, messages: list[dict], dictionaries: list[dict]) -> list[Finding]:
        validate_messages(messages)
        dictionary_patterns = []
        for row in dictionaries:
            category, value = row.get("category"), row.get("entry_value", row.get("value"))
            mode = row.get("match_mode", "exact")
            if (
                category not in CATEGORIES
                or not isinstance(value, str)
                or not 1 <= len(value) <= 2048
                or mode not in {"exact", "case_insensitive"}
            ):
                raise DetectorError("invalid_dictionary")
            dictionary_patterns.append(
                (category, re.compile(re.escape(value), re.IGNORECASE if mode == "case_insensitive" else 0))
            )
        results = {}
        for index, message in enumerate(messages):
            text = message["content"]

            def add(start, end, category, score, recognizer, index=index):
                identity = (index, start, end, category)
                if identity not in results or results[identity].score < score:
                    results[identity] = Finding(index, start, end, category, score, recognizer)

            for language in LANGUAGES:
                for f in self.engine.analyze(
                    text=text, language=language, entities=["EMAIL", "PHONE"], score_threshold=0.4
                ):
                    threshold = 0.5 if f.entity_type == "EMAIL" else 0.4
                    start, end = _recognizer_span(text, f.start, f.end, f.entity_type)
                    if f.score >= threshold and _boundary(text, start, end):
                        add(
                            start,
                            end,
                            f.entity_type,
                            f.score,
                            "email-local-v1" if f.entity_type == "EMAIL" else "phone-v1",
                        )
            for match in IP_CANDIDATE.finditer(text):
                try:
                    candidate = match.group().rstrip(".")
                    address = ipaddress.ip_address(candidate)
                    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
                    if any(
                        address in network or (mapped is not None and mapped in network)
                        for network in self.networks
                    ):
                        add(
                            match.start(),
                            match.start() + len(candidate),
                            "IP_ADDRESS",
                            1.0,
                            "protected-ip-v1",
                        )
                except ValueError:
                    pass
            for match in HOST_CANDIDATE.finditer(text):
                if match.group().lower().endswith(self.suffixes):
                    add(*match.span(), "INTERNAL_HOSTNAME", 1.0, "hostname-suffix-v1")
            for category, recognizer, pattern in COMPILED_SIGNATURES:
                for match in pattern.finditer(text):
                    add(*match.span(), category, 1.0, recognizer)
            for match in JWT_CANDIDATE.finditer(text):
                if _valid_jwt(match.group()):
                    add(*match.span(), "JWT", 1.0, "jwt-structure-v1")
            for match in TOKEN_ASSIGNMENT.finditer(text):
                start, end = match.span(1)
                if not any(
                    f.message_index == index
                    and f.start < end
                    and start < f.end
                    and f.category in {"API_KEY", "ACCESS_TOKEN", "JWT"}
                    for f in results.values()
                ):
                    add(start, end, "ACCESS_TOKEN", 0.8, "assigned-token-v1")
            for category, pattern in dictionary_patterns:
                for match in pattern.finditer(text):
                    if _boundary(text, *match.span(), hostname=category == "INTERNAL_HOSTNAME"):
                        add(*match.span(), category, 1.0, "dictionary-v1")
        return sorted(results.values(), key=lambda f: (f.message_index, f.start, f.end, f.category))
