"""Ortak yardımcılar."""
import datetime as dt


def now_utc() -> dt.datetime:
    """Naive UTC zaman damgası.

    `datetime.utcnow()` Python 3.12+'da deprecated; tz-aware'e geçmek ise imza/hash
    kanonik gösterimindeki `isoformat()` çıktısını değiştirip imza uyumunu bozar.
    Bu yüzden tz-aware UTC alıp tzinfo'yu düşürerek mevcut (naive) formatı koruyoruz.
    """
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
