# 🔍 PortAraştırıcı – GUI + CLI Destekli Gelişmiş Port Tarayıcı

PortAraştırıcı, hem grafik arayüz (GUI) hem de komut satırı (CLI) üzerinden çalışan güçlü bir port tarama ve güvenlik analiz aracıdır. Nmap entegrasyonu ile ağdaki cihazların açık TCP/UDP portlarını analiz eder, servis tespiti yapar, CVE veritabanı ile eşleştirir ve çıktılarını HTML olarak kaydeder.

## 🚀 Özellikler

- ✅ TCP/UDP port tarama
- 🌐 Web servis analizi (HTTP banner, port yorumları)
- 📚 CVE veritabanı eşleştirme
- 🖥 GUI (tkinter) arayüz ile kolay kullanım
- 🧪 CLI modunda hızlı tarama desteği
- 💾 HTML çıktısı ve SQLite veritabanı kayıt sistemi
- 🧠 Basit, kullanıcı dostu ve Python tabanlı

## 🖥 Kullanım

### 1. Grafik Arayüz (GUI) ile:
```bash
python portarayıcı.py
```
GUI penceresi otomatik olarak açılır.

### 2. Komut Satırı (CLI) ile:
```bash
python portarayıcı.py --cli --hedef 192.168.1.1
```

---

## ⚙️ Gereksinimler

```bash
pip install -r requirements.txt
```

- Python 3.9+
- nmap (sisteme kurulu olmalı)

---

## 📄 Örnek Kullanım

- IP gir → port aralığı seç → tara → sonuçlar HTML olarak kaydedilir
- GUI üzerinden kullanıcı IP, port aralığı ve protokol seçebilir

---

## 📂 Proje Yapısı

```
advanced-port-scanner/
├── portarayıcı.py
├── README.md
├── requirements.txt
```

---

## 📜 Lisans

MIT © 2025 Burak BALTA
