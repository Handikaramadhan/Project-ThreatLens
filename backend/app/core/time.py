from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return a UTC timestamp without tzinfo for existing naive DB columns."""
    return datetime.now(UTC).replace(tzinfo=None)
