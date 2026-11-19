"""Value redaction shared by phase subprocesses and the repo-free collector."""

import os
import re


def redact_values(value, *, secrets=(), environment=None):
    # Kept self-contained: inspect.getsource embeds this exact function into the
    # stdlib-only collector, which must work even before the repository exists.
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value or "")
    values = list(secrets)
    for key, item in (os.environ if environment is None else environment).items():
        if any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
            values.append(item)
    for secret in sorted((str(x) for x in values if x), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(--token(?:=|\s+))\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(Bearer\s+)\S+", r"\1[REDACTED]", text)
    # Header values, not prose such as 'no basic auth credentials' or
    # 'Your authorization token has expired'. Retain the diagnostic sentence.
    text = re.sub(
        r"(?i)(Authorization[ \t]*:[ \t]*(?:(?:Basic|Bearer)[ \t]+)?)\S+", r"\1[REDACTED]", text
    )
    text = re.sub(r"(?im)^([ \t]*Basic[ \t]+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED]", text)
    text = re.sub(
        r"(?i)(\baws_(?:secret_access_key|session_token|access_key_id)\b[\"']?\s*[:=]\s*[\"']?)[^\s,;\"']+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?<=:)\d{12}(?=:)", "[account-redacted]", text)
    return text
