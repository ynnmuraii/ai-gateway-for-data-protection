import base64
import hashlib
import hmac
import re
import struct
from uuid import UUID

from .types import CATEGORIES, DetectorError, Finding, ProtectionResult, validate_messages

MARKER_PATTERN = re.compile(r"\[(?:" + "|".join(CATEGORIES) + r")_[A-Z2-7]{52}\]")


def frame(parts: list[bytes]) -> bytes:
    output = bytearray()
    for part in parts:
        if not isinstance(part, bytes) or len(part) > 0xFFFFFFFF:
            raise DetectorError("invalid_pseudonym_frame")
        output.extend(struct.pack(">I", len(part)))
        output.extend(part)
    return bytes(output)


def marker_for(category: str, value: str, scope: dict, key: bytes) -> str:
    try:
        if category not in CATEGORIES or not isinstance(key, bytes) or len(key) < 32:
            raise ValueError
        fields = [
            "gateway-pseudonym-v1",
            str(UUID(str(scope["integration_id"]))),
            scope["issuer"],
            scope["sub"],
            str(UUID(str(scope["user_id"]))),
            scope["chat_id"],
            category,
            value,
        ]
        if (
            not all(isinstance(v, str) for v in fields)
            or not 1 <= len(fields[2]) <= 2048
            or not 1 <= len(fields[3]) <= 255
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", fields[5])
        ):
            raise ValueError
        digest = hmac.new(key, frame([v.encode("utf-8") for v in fields]), hashlib.sha256).digest()
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise DetectorError("invalid_pseudonym_scope") from None
    return f"[{category}_{base64.b32encode(digest).decode('ascii').rstrip('=')}]"


def protect(
    messages: list[dict], findings: list[Finding], actions: dict[str, str], scope: dict, key: bytes
) -> ProtectionResult:
    validate_messages(messages)
    if set(actions) != set(CATEGORIES) or any(v not in {"ALLOW", "MASK", "BLOCK"} for v in actions.values()):
        raise DetectorError("invalid_policy")
    unique = {}
    for f in findings:
        if (
            not isinstance(f, Finding)
            or f.category not in CATEGORIES
            or type(f.message_index) is not int
            or not 0 <= f.message_index < len(messages)
            or type(f.start) is not int
            or type(f.end) is not int
            or not 0 <= f.start < f.end <= len(messages[f.message_index]["content"])
        ):
            raise DetectorError("invalid_finding")
        unique[(f.message_index, f.start, f.end, f.category)] = f
    counts = {category: sum(f.category == category for f in unique.values()) for category in CATEGORIES}
    counts = {k: v for k, v in counts.items() if v}
    if any(actions[f.category] == "BLOCK" for f in unique.values()):
        return ProtectionResult("BLOCK", [], counts)
    masks = sorted(
        (f for f in unique.values() if actions[f.category] == "MASK"),
        key=lambda f: (f.message_index, f.start, -f.end, f.category),
    )
    if not masks:
        return ProtectionResult("ALLOW", [m.copy() for m in messages], counts)
    resolved = []
    for current in masks:
        if resolved:
            previous = resolved[-1]
            if previous.message_index == current.message_index and current.start < previous.end:
                # Masking the containing value also covers nested findings, e.g. a host inside an email.
                if current.end <= previous.end and (current.start, current.end) != (previous.start, previous.end):
                    continue
                raise DetectorError("ambiguous_mask_overlap")
        resolved.append(current)
    masks = resolved
    literal_markers = {
        match.group()
        for message in messages
        if message["role"] != "assistant"
        for match in MARKER_PATTERN.finditer(message["content"])
    }
    # An assistant can echo our marker into history. It is ordinary text, never an auth or scan bypass (ADR-007).
    marker_values = {}
    output = []
    for index, message in enumerate(messages):
        text, cursor, segments = message["content"], 0, []
        for f in (f for f in masks if f.message_index == index):
            value = text[f.start : f.end]
            marker = marker_for(f.category, value, scope, key)
            if marker in literal_markers:
                raise DetectorError("literal_marker_conflict")
            identity = (f.category, value)
            if marker in marker_values and marker_values[marker] != identity:
                raise DetectorError("pseudonym_collision")
            marker_values[marker] = identity
            segments.extend((text[cursor : f.start], marker))
            cursor = f.end
        segments.append(text[cursor:])
        output.append({"role": message["role"], "content": "".join(segments)})
    return ProtectionResult("MASK", output, counts)
