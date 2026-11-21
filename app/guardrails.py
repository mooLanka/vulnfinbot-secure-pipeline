import base64
import binascii
import html
import re
import unicodedata

MAX_MESSAGE_LENGTH = 1000
MAX_RESPONSE_LENGTH = 2000

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

REDACTED = "[redacted]"
OUTPUT_FALLBACK = "I cannot share that information. Ask me a general financial question."

class InputValidationError(ValueError):
    pass

class OutputValidationError(ValueError):
    pass

def validate_message(value):
    if value is None:
        raise InputValidationError("Field 'message' is required.")
    if not isinstance(value, str):
        raise InputValidationError("Field 'message' must be a string.")
    if _CONTROL_CHARS.search(value):
        raise InputValidationError("Field 'message' contains unsupported control characters.")
    message = value.strip()
    if not message:
        raise InputValidationError("Field 'message' must not be empty.")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise InputValidationError(f"Field 'message' must not exceed {MAX_MESSAGE_LENGTH} characters.")
    return message

RISK_PATTERNS = {
    "prompt_injection": (
        re.compile(r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|messages?)", re.I),
        re.compile(r"disregard\s+(?:all\s+|the\s+)?(?:previous|prior|above|system|developer)", re.I),
        re.compile(r"forget\s+(?:all\s+|your\s+)?(?:previous|prior|above|system|earlier)", re.I),
        re.compile(r"\byou\s+are\s+now\b", re.I),
        re.compile(r"\b(?:developer|dan|jailbreak|god)\s+mode\b", re.I),
        re.compile(r"игнорируй\s+(?:все\s+|предыдущие|прошлые|выше)", re.I),
        re.compile(r"забудь\s+(?:все\s+)?(?:предыдущие|прошлые|свои)\s+инструкции", re.I),
    ),
    "system_prompt_disclosure": (
        re.compile(r"\b(?:system|developer|initial|hidden|internal)\s+prompt\b", re.I),
        re.compile(r"\b(?:print|show|reveal|repeat|output|display|leak|dump)\b[^.]{0,40}\b(?:instructions?|prompt|rules|configuration|config)\b", re.I),
        re.compile(r"системн\w*\s+промпт", re.I),
        re.compile(r"(?:покажи|выведи|распечатай)\s+(?:свои\s+)?(?:системные\s+)?(?:скрытые\s+)?(?:внутренние\s+)?инструкции", re.I),
        re.compile(r"\brepeat\b[^.]{0,40}\b(?:everything|text|words?)\b[^.]{0,25}\babove\b", re.I),
    ),
    "sensitive_data_disclosure": (
        re.compile(r"\b(?:show|reveal|print|give|leak|dump|tell)\b[^.]{0,40}\b(?:password|api[\s_-]?key|token|secret|credential)", re.I),
        re.compile(r"\b(?:connection\s+string|database\s+url|\.env|private\s+key)\b", re.I),
        re.compile(r"(?:выведи|покажи|скажи)[^.]{0,20}(?:пароль|ключ|секрет)", re.I),
        re.compile(r"\b(?:other|another|all)\s+(?:users?|customers?|clients?|accounts?)\b", re.I),
        re.compile(r"\b(?:card\s+number|cvv|iban|ssn|passport)\b", re.I),
    ),
    "unauthorized_tool_usage": (
        re.compile(r"\b(?:transfer|send|wire|withdraw|move)\s+(?:\d[\d.,]*|\$|€|£|all|my)\b", re.I),
        re.compile(r"\b(?:execute|run)\b[^.]{0,30}\b(?:code|command|shell|python|sql|script)", re.I),
        re.compile(r"(?:os\.system|subprocess|__import__|rm\s+-rf|drop\s+table|delete\s+from)", re.I),
        re.compile(r"переведи\s+\d+|выполни\s+(?:код|команду)", re.I),
    ),
}

REFUSALS = {
    "prompt_injection": "I cannot change or ignore my operating instructions. I can still help with general financial questions.",
    "system_prompt_disclosure": "I cannot share internal instructions or configuration. Ask me a general finance question instead.",
    "sensitive_data_disclosure": "I cannot provide credentials or personal and account data of other people.",
    "unauthorized_tool_usage": "I have no permission to move money, run code or call tools. I can only provide general information.",
}
DEFAULT_REFUSAL = "I cannot help with that request, but I can answer general financial questions."

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']+", re.I),
)

def _normalize(text):
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return re.sub(r"\s+", " ", text).strip()

def classify_request(message):
    found = []
    normalized = _normalize(message)
    for category, patterns in RISK_PATTERNS.items():
        if category not in found and any(p.search(normalized) for p in patterns):
            found.append(category)
    return tuple(found)

def sanitize_output(text, *, confidential_markers=()):
    if not isinstance(text, str):
        raise OutputValidationError("Model output must be a string.")
    cleaned = _CONTROL_CHARS.sub("", _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text)))
    for marker in confidential_markers:
        if marker and marker in cleaned:
            return OUTPUT_FALLBACK
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub(REDACTED, cleaned)
    cleaned = re.sub(r"(?i)javascript\s*:", "blocked:", cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > MAX_RESPONSE_LENGTH:
        cleaned = cleaned[:MAX_RESPONSE_LENGTH].rstrip() + " ...[truncated]"
    if not cleaned:
        return OUTPUT_FALLBACK
    return html.escape(cleaned, quote=True)
