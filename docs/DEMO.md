# Aegis — Demo Kılavuzu (GIF/ekran görüntüsü kaydı için)

Bu kılavuz, dört SOC alanını + sertleştirme özelliklerini tek akışta gösterir.
Ekran kaydı için: **Windows** → `Win+G` (Xbox Game Bar) veya [ScreenToGif](https://www.screentogif.com/).
Kaydı `docs/screenshots/` altına koyabilirsiniz.

## Ön koşul (tek seferlik)
```powershell
# Her modül için venv + bağımlılıklar (bkz. README), ve ML modelleri:
cd F:\aegis\ml
python scripts\..\..\scripts\fetch_datasets.py   # (ops.) gerçek veri
python -m aegis_ml.train
```

## Tek komutla tam demo
```powershell
F:\aegis\scripts\demo.ps1
```
Servisleri başlatır (SOC 8000 · ML 8001 · Lab 5001 · UI 5173), dört alanı doldurur,
kripto kurcalama tetikler ve dashboard'u açar.

## Demo senaryoları (kaydederken anlatılacaklar)
1. **Blue (tespit):** `seed_demo` → dashboard'da brute-force, şüpheli komut/süreç alarmları.
   Aynı brute-force tekrarı tek alarmda **×N** sayacıyla toplanır (korelasyon/dedup).
2. **Red (ofansif):** scanner → **SQLi · XSS · Open-Redirect** + açık portlar; "Tarama & Varlıklar"
   panelinde görünür.
3. **ML:** `ml_demo` → "ML Tespitleri" panelinde phishing (skor ~0.94) + NIDS anomali (~0.98).
4. **Kripto:** `tamper_demo` ile bir log kaydı değiştirilince **"⚠️ Kurcalama!"** rozeti +
   `/api/crypto/verify-signatures` geçersiz imzayı raporlar.
5. **Gerçek-zaman:** Yeni alarm geldiğinde sayfa **SSE** ile anında güncellenir → başlıkta "⚡ canlı".
6. **Güvenli ajan + FIM/auth:** ajanı `--config config.secure.yaml` ile çalıştırıp
   `lab/watched/critical.conf`'u değiştir → **file-integrity** alarmı; `lab/auth.log`'a
   başarısız giriş satırı ekle → **brute-force** alarmı (imzalı/şifreli kanaldan).

## Manuel adım adım
```powershell
# 1) Servisler (4 ayrı pencere) — veya scripts\start_all.ps1
# 2) Blue:  python scripts\seed_demo.py
# 3) Red:   cd scanner; python -m aegis_scanner.main --target 127.0.0.1
# 4) ML:    python scripts\ml_demo.py
# 5) Kripto: python scripts\tamper_demo.py --id 1   (sonra /api/integrity/verify)
# 6) FIM/auth: cd agent; python -m aegis_agent.main --config config.secure.yaml
```

## Önerilen kayıt çerçevesi
- Dashboard üst kartlar (alarm sayıları + 🔒 bütünlük), Önem Dağılımı çubuğu,
  Tarama & Varlıklar + ML Tespitleri panelleri, Alarmlar tablosu (×N + durum), Telemetri akışı (🔒 secure).
