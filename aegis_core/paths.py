import re

_DIGIT_RUN = re.compile(r"\d+")


def normalize_path(path: str) -> str:
    """Collapse numeric path segments so /orders/7/ and /orders/8/ are seen
    as the same logical endpoint instead of two distinct ones."""
    return _DIGIT_RUN.sub("{id}", path)
