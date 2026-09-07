import logging
from functools import lru_cache
from math import asin, cos, radians, sin, sqrt

from django.conf import settings

logger = logging.getLogger(__name__)

EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in kilometers."""
    lat1, lon1, lat2, lon2 = map(radians, (lat1, lon1, lat2, lon2))
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    a = sin(delta_lat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(delta_lon / 2) ** 2
    return 2 * EARTH_RADIUS_KM * asin(sqrt(a))


@lru_cache(maxsize=1)
def _get_reader():
    db_path = settings.AEGIS_GEOIP_DB_PATH
    if not db_path:
        return None
    try:
        import geoip2.database

        return geoip2.database.Reader(db_path)
    except (ImportError, OSError) as exc:
        logger.warning("GeoIP database unavailable at %s: %s", db_path, exc)
        return None


def locate_ip(ip_address: str | None) -> tuple[float, float] | None:
    """(lat, lon) for an IP address, or None if it can't be resolved.

    Returns None (rather than raising) whenever a MaxMind GeoLite2 database
    isn't configured or the address isn't in it -- impossible-travel
    detection simply has nothing to compare against until one is.
    """
    if not ip_address:
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        response = reader.city(ip_address)
    except Exception as exc:  # geoip2 raises its own AddressNotFoundError etc.
        logger.debug("Could not locate %s: %s", ip_address, exc)
        return None
    if response.location.latitude is None or response.location.longitude is None:
        return None
    return response.location.latitude, response.location.longitude
