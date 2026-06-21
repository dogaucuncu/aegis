# Aegis — Tehdit Modeli (özet)

Eğitim/portföy amaçlı bir mini-SOC. Aşağıda korunan varlıklar, saldırgan yetenekleri,
karşı önlemler ve bilinen sınırlar özetlenir.

## Varlıklar
- Telemetri olayları ve alarmlar (bütünlük + kaynak kanıtı kritik).
- Ajan↔sunucu kanalı (gizlilik + kimlik).
- Tespit kuralları ve ML modelleri.

## Saldırgan modeli
- **Ağ üzerindeki pasif/aktif saldırgan:** trafiği dinler, yakalar, yeniden gönderir.
- **Yetkisiz istemci:** API'ye sahte olay enjekte etmeye çalışır.
- **İçeriden kurcalama:** depolanmış logları geçmişe dönük değiştirmeye çalışır.

## Önlemler (uygulandı)
| Tehdit | Önlem |
|--------|-------|
| Sahte olay enjeksiyonu | API anahtarı auth (`X-API-Key`) + güvenli uçta Ed25519 imza |
| Dinleme (gizlilik) | AES-256-GCM (ECDH+HKDF türetilmiş anahtar) + opsiyonel mTLS |
| Anahtar sızıntısı (at-rest AES) | AES diskte tutulmaz; X25519 ECDH ile türetilir |
| Yeniden gönderme (replay) | Zaman damgası tazeliği (±5 dk) + nonce tekrar reddi |
| Log kurcalama | SHA-256 hash-zinciri (tamper-evident) + imza denetimi |
| İstek seli (DoS) | Per-IP rate limit (yapılandırılabilir) |
| Yetkisiz origin | CORS allowlist |

## Bilinen sınırlar / kapsam dışı
- mTLS canlı uçtan uca, geliştirme makinesindeki TLS araya-girmesi (Norton) nedeniyle
  yalnızca bellek-içi testle doğrulandı (`scripts/mtls_selftest.py`).
- Hash-zinciri global; çok-süreçli/dağıtık dağıtımda satır-bazlı DB kilidi gerekir
  (tek-süreçte threading kilidi ile serileştirilir).
- ML NIDS, gerçek canlı akış özelliklerini değil, akış-vektörlerini skorlar (flow toplayıcı yok).
- Ofansif tarayıcı yalnızca yetkili/lab hedefleri içindir.
- Anahtar rotasyonu, gizli-yönetim vault'u ve denetim-kaydı imzalama anahtarı koruması kapsam dışı.
