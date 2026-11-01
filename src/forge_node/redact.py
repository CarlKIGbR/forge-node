"""Redaction (Design 4.1 `logs.unit`, 8.4): wird am Node VOR dem Schreiben und am Hub VOR dem Speichern angewandt; roher Output wird nie gespeichert.
Muster aus dem Secret-Scan der Inventur. Zwei Stufen: `light` (Token-Praefixe, JWT, PEM, URL-Credentials, Schluessel=Wert) fuer Inventar-/Audit-Daten, in denen Digests und
Git-Revisionen erhalten bleiben muessen; `full` (zusaetzlich >= 32 Zeichen lange base64/hex-Folgen) fuer Log-Text. Ueberredaktion ist die sichere Richtung."""
import re

REDACTION_VERSION = 2          # 2: values under secret-named keys are redacted by key (api_key, forge.api_key, token, ...)
MARK = "[REDACTED]"

_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|\Z)")
_URL_CRED = re.compile(r"(?<=://)[^\s/:@]+:[^\s/@]+@")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.?[A-Za-z0-9_-]*")
_PREFIXES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|ghs_[A-Za-z0-9]{8,}|ghu_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|xox[a-zA-Z]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{8,}|ASIA[0-9A-Z]{8,}|hf_[A-Za-z0-9]{8,})"
)
_KEYWORDS = r"(?:password|passwd|pwd|passphrase|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|bearer|authorization|credentials?)"
_KV = re.compile(
    r"(?i)((?:[\"']?)\b[A-Za-z0-9_.-]*" + _KEYWORDS + r"[A-Za-z0-9_.-]*(?:[\"']?)\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|(?:Bearer|Basic|Token)\s+[^\s,;&\"']+|[^\s,;&\"']+)"
)
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=-]{8,}")
_LONG = re.compile(r"(?<![A-Za-z0-9+/_=-])(?<!sha256:)(?<!sha256-)[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])")


def _long(m: re.Match) -> str:
    t = m.group(0)
    if any(c.isdigit() for c in t) and any(c.isalpha() for c in t):
        return MARK
    return t


def redact_light(text: str) -> str:
    if not text:
        return text
    text = _PEM.sub(MARK, text)
    text = _URL_CRED.sub(MARK + "@", text)
    text = _JWT.sub(MARK, text)
    text = _PREFIXES.sub(MARK, text)
    text = _KV.sub(lambda m: m.group(1) + MARK, text)
    text = _BEARER.sub(lambda m: m.group(1) + m.group(2) + MARK, text)
    return text


def redact_full(text: str) -> str:
    return _LONG.sub(_long, redact_light(text))


# Secret-named keys: a value whose KEY says what it is needs no recognisable shape (`{"forge.api_key": "hunter2-plain"}`). Matched on the key with separators and case removed, so
# api_key / api-key / ApiKey / forge.api_key / FORGE_API_KEY / x-auth-token all hit. Over-redaction is the safe direction.
_SECRET_KEY = re.compile(r"(?:passw(?:or)?d|passwd|pwd|passphrase|secret|token|apikey|accesskey|secretkey|privatekey|signingkey|encryptionkey|bearer|authorization|credential|cookie|sessionid|clientsecret)")


def secret_key(key) -> bool:
    return isinstance(key, str) and bool(_SECRET_KEY.search(re.sub(r"[^a-z0-9]", "", key.lower())))


def _blank(v):
    """Everything below a secret-named key is replaced: strings by the mark, containers leaf by leaf; numbers/booleans/None stay (a count of tokens is not a token)."""
    if isinstance(v, str):
        return MARK
    if isinstance(v, list):
        return [_blank(x) for x in v]
    if isinstance(v, dict):
        return {k: _blank(x) for k, x in v.items()}
    return v


def redact_obj(obj, full: bool = False):
    """Recursively over all strings (values) AND by key: values under secret-named keys are replaced whole. Keys themselves are not rewritten."""
    fn = redact_full if full else redact_light
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [redact_obj(x, full) for x in obj]
    if isinstance(obj, dict):
        return {k: (_blank(v) if secret_key(k) else redact_obj(v, full)) for k, v in obj.items()}
    return obj
