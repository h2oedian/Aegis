import ipaddress
import socket
from urllib.parse import urlsplit


class UnsafeTargetError(ValueError):
    pass


def validate_target(base_url: str, allow_public_target: bool = False) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetError("Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("Credentials are not allowed inside the target URL.")
    if parsed.query or parsed.fragment:
        raise UnsafeTargetError("Target URL must not contain a query or fragment.")

    hostname = parsed.hostname.lower()
    if hostname == "localhost":
        return base_url.rstrip("/")

    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(hostname, parsed.port)
            }
        except socket.gaierror as exc:
            raise UnsafeTargetError(f"Target hostname could not be resolved: {hostname}") from exc

    is_local = bool(addresses) and all(
        address.is_private or address.is_loopback or address.is_link_local
        for address in addresses
    )
    if not is_local and not allow_public_target:
        raise UnsafeTargetError(
            "Public targets are blocked. Use --allow-public-target only with explicit authorization."
        )
    return base_url.rstrip("/")

