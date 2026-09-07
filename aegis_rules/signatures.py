import re
from collections.abc import Mapping
from urllib.parse import unquote

from .base import RuleResult

SQLI_PATTERN = re.compile(
    r"(\bunion\b\s+\bselect\b)|(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"
    r"|(--\s)|(;\s*--)|(\bdrop\b\s+\btable\b)|(\bselect\b.*\bfrom\b)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(
    r"(<script\b)|(javascript:)|(on(error|load|click|mouseover)\s*=)|(<img[^>]+src)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./)|(\.\.\\)|(%2e%2e(%2f|/))|(/etc/passwd)|(\\windows\\system32)",
    re.IGNORECASE,
)

# name, pattern, score contributed when matched
SIGNATURES = (
    ("sqli", SQLI_PATTERN, 50.0),
    ("xss", XSS_PATTERN, 50.0),
    ("path_traversal", PATH_TRAVERSAL_PATTERN, 60.0),
)


def scan_injection_signatures(path: str, query_params: Mapping[str, str]) -> RuleResult:
    """Score ``path``/``query_params`` against known SQLi/XSS/traversal patterns.

    More distinct signatures matching yields a higher score instead of a
    plain pass/fail, so a request tripping two patterns at once outranks
    one tripping a single, possibly-coincidental pattern.
    """
    haystack = unquote(" ".join([path, *query_params.values()]))
    matched = [name for name, pattern, _ in SIGNATURES if pattern.search(haystack)]
    score = min(100.0, sum(weight for name, _, weight in SIGNATURES if name in matched))
    return RuleResult(
        rule="injection_signature",
        score=score,
        triggered=bool(matched),
        detail=", ".join(matched),
    )
