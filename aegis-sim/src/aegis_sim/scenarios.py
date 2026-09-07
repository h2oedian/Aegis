from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestSpec:
    method: str
    path: str
    params: dict[str, str] | None = None
    json: dict[str, str] | None = None
    headers: dict[str, str] | None = None


def brute_force(username: str, password_prefix: str) -> Iterator[RequestSpec]:
    attempt = 1
    while True:
        yield RequestSpec(
            method="POST",
            path="/api/auth/login/",
            json={"username": username, "password": f"{password_prefix}{attempt}"},
        )
        attempt += 1


def product_scrape() -> Iterator[RequestSpec]:
    page = 1
    while True:
        yield RequestSpec(
            method="GET", path="/api/products/", params={"page": str(page)}
        )
        page = 1 if page >= 100 else page + 1


def id_enumeration(start_id: int, token: str | None) -> Iterator[RequestSpec]:
    current_id = start_id
    headers = {"Authorization": f"Bearer {token}"} if token else None
    while True:
        yield RequestSpec(
            method="GET",
            path=f"/api/orders/{current_id}/",
            headers=headers,
        )
        current_id += 1


def injection_probes() -> Iterator[RequestSpec]:
    payloads = (
        "' OR '1'='1",
        "1 UNION SELECT NULL--",
        "<script>alert('aegis')</script>",
        "<img src=x onerror=alert('aegis')>",
    )
    index = 0
    while True:
        yield RequestSpec(
            method="GET",
            path="/api/products/",
            params={"search": payloads[index]},
        )
        index = (index + 1) % len(payloads)


def create_scenario(
    name: str,
    *,
    username: str,
    password_prefix: str,
    start_id: int,
    token: str | None,
) -> Iterator[RequestSpec]:
    scenarios = {
        "brute-force": lambda: brute_force(username, password_prefix),
        "scrape": product_scrape,
        "id-enumeration": lambda: id_enumeration(start_id, token),
        "injection-probes": injection_probes,
    }
    return scenarios[name]()

