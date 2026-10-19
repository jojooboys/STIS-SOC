"""Datetime serialization helpers used by API models."""
from datetime import timezone


def isoformat_utc(value):
    """Serialize a datetime as an unambiguous UTC ISO-8601 value.

    SQLite commonly returns a naive datetime even when the value was created
    with UTC tzinfo. Treat those persisted values as UTC so browsers do not
    interpret them as local time and shift the display by seven hours.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
