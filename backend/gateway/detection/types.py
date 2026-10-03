from dataclasses import dataclass

CATEGORIES = ("EMAIL", "PHONE", "IP_ADDRESS", "INTERNAL_HOSTNAME", "API_KEY", "ACCESS_TOKEN", "JWT")


class DetectorError(Exception):
    """Safe machine-readable error; no input text or recognizer exceptions."""

    def __init__(self, code: str, status_code: int = 503):
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class Finding:
    message_index: int
    start: int
    end: int
    category: str
    score: float
    recognizer_id: str


@dataclass(frozen=True, slots=True)
class ProtectionResult:
    decision: str
    messages: list[dict]
    counts: dict[str, int]


def validate_messages(messages):
    if not isinstance(messages, list) or not messages:
        raise DetectorError("invalid_messages", 400)
    for message in messages:
        if (
            not isinstance(message, dict)
            or set(message) != {"role", "content"}
            or message["role"] not in {"system", "user", "assistant"}
            or not isinstance(message["content"], str)
        ):
            raise DetectorError("invalid_messages", 400)
