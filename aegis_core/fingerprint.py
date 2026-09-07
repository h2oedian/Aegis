import hashlib

# Headers that describe the client software, not its network location --
# stable for the same browser/app across a session, distinct across devices.
FINGERPRINT_HEADERS = ("HTTP_USER_AGENT", "HTTP_ACCEPT_LANGUAGE", "HTTP_ACCEPT_ENCODING")


def compute_fingerprint(request) -> str:
    """A stable hash identifying "this device", for binding to a token."""
    raw = "|".join(request.META.get(header, "") for header in FINGERPRINT_HEADERS)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
