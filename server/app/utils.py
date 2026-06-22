"""Common helpers."""
import datetime as dt


def now_utc() -> dt.datetime:
    """Naive UTC timestamp.

    `datetime.utcnow()` is deprecated in Python 3.12+; switching to tz-aware would change
    the `isoformat()` output in the signature/hash canonical representation and break
    signature compatibility. So we take tz-aware UTC and drop tzinfo to preserve the
    existing (naive) format.
    """
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
