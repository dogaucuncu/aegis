"""Veritabanı modelleri: Event (ham telemetri) ve Alert (kural eşleşmeleri)."""
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.types import JSON

from .database import Base
from .utils import now_utc


class Event(Base):
    """Ajanlardan gelen tek bir telemetri olayı.

    `prev_hash` + `hash` alanları, kurcalanmaya-dayanıklı (tamper-evident) bir
    hash-zinciri oluşturur. Faz 2'de buna Ed25519 imza eklenecek.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(128), index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=now_utc, index=True)
    data = Column(JSON, nullable=False, default=dict)

    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=True, index=True)

    # Faz 2: ajanın Ed25519 imzası (base64). Güvenli modda dolu, düz modda NULL.
    signature = Column(String(128), nullable=True)

    @property
    def signed(self) -> bool:
        """Olay güvenli (imzalı) kanaldan mı geldi?"""
        return self.signature is not None


class ChainHead(Base):
    """Hash-zinciri başı (tek satır, id=1).

    Eşzamanlı append'lerde zincirin çatallanmasını önlemek için kilit noktası:
    PostgreSQL'de `SELECT ... FOR UPDATE` ile satır kilitlenir (çok-süreçli/dağıtık);
    SQLite'da süreç-içi threading kilidi yeterlidir.
    """

    __tablename__ = "chain_head"

    id = Column(Integer, primary_key=True)
    last_hash = Column(String(64), nullable=True)


class SeenNonce(Base):
    """Replay koruması: işlenmiş güvenli-zarf nonce'ları (TTL'li).

    Aynı AES-GCM nonce'lı bir zarfın yeniden gönderimi (replay) reddedilir.
    """

    __tablename__ = "seen_nonces"

    id = Column(Integer, primary_key=True)
    agent_id = Column(String(128), index=True, nullable=False)
    nonce = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=now_utc, index=True)


class Alert(Base):
    """Kural motorunun bir olaydan ürettiği alarm."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=now_utc, index=True)
    rule_id = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), index=True, default="medium")
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    agent_id = Column(String(128), index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    status = Column(String(16), default="open", index=True)

    # Korelasyon/dedup: aynı dedup_key'li AÇIK alarm tekrar üretilmez, count artırılır.
    dedup_key = Column(String(160), index=True)
    count = Column(Integer, default=1, nullable=False)
    last_seen = Column(DateTime, default=now_utc, index=True)
