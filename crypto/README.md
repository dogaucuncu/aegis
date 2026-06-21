# aegis-crypto — paylaşılan kriptografi kütüphanesi

Ajan ve sunucunun ortak kullandığı, kurulabilir (editable) küçük kütüphane.

- **Ed25519** — olay imzalama / doğrulama (`sign`, `verify`)
- **AES-256-GCM** — kimlik-doğrulamalı şifreleme (`encrypt`, `decrypt`)
- **X25519 + HKDF** — ECDH ile paylaşılan AES anahtarı türetme (`derive_aes_key`)
- **Kanonik JSON** — imza/şifre için deterministik bytes (`canonical_bytes`, `event_canonical`)
- **keys** — Ed25519/X25519/AES anahtar üret/kaydet/yükle

## Kurulum
```powershell
pip install -e crypto      # repo kökünden
```
İki tarafın da aynı bytes'ı üretmesi için `event_canonical` her iki yanda kullanılır.
