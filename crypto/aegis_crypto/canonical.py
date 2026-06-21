"""Deterministik (kanonik) JSON serileştirme.

İmza ve şifreleme aynı byte dizisi üzerinde çalışmalı; bu yüzden anahtarlar sıralanır
ve boşluk kullanılmaz. İmzalayan (ajan) ve doğrulayan (sunucu) tarafların ürettiği
bytes birebir aynı olmalıdır.
"""
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def event_canonical(agent_id: str, event_type: str, timestamp: Any, data: Any) -> bytes:
    """Bir olayın imzalanacak/doğrulanacak kanonik byte gösterimi.

    Ajan ve sunucu BU fonksiyonu kullanarak birebir aynı bytes üretir.
    `timestamp` her iki tarafta da ISO-8601 string olmalıdır.
    """
    return canonical_bytes(
        {
            "agent_id": agent_id,
            "event_type": event_type,
            "timestamp": str(timestamp),
            "data": data,
        }
    )
