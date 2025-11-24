<div align="center">

🔥 **ZNUZHGFW**  
**Red-Team Style Web Vulnerability Scanner**

_Aggressive. Fast. Modular. Offensive Mindset. Defensive Purpose._

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-Red%20Team-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Made%20By-ZNUZHG-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-black?style=for-the-badge" />
</p>

---

## 🩸 **Nedir Bu?**

**ZNUZHGFW**, agresif ve Red-Team odaklı bir web güvenlik tarayıcısıdır.  
Pentester'lar, bug bounty avcıları ve güvenlik araştırmacıları için tasarlanmış modüler, hızlı ve genişletilebilir bir framework.

### ✔ **Dahili Modüller**
- 🧨 **SQL Injection Scanner** (Boolean / Error / Time)
- ⚔️ **XSS Scanner** (Reflected / DOM)
- 📂 **LFI / Path Traversal**
- 🔁 **Open Redirect**
- 🧱 **Security Headers Analyzer**
- 🚦 **Rate-Limit Tester**
- 🛡️ **WAF Detector** (Cloudflare / Sucuri basic)
- 🧠 **SSTI Detector**
- 📜 **CRLF Injection**
- 🧭 **HTTP Methods Analyzer**
- 📁 **Directory Brute-Force**
- 🕷️ **Crawler** (Depth-controlled spider)
- 🔥 **Multithreaded Engine**
- 📄 **HTML, Markdown, JSON Report Generator**

---

## ⚡ Kurulum

### 🔧 PyPI (Önerilen)

```bash
pip install znuzhgfw

📌 Kaynak Koddan

git clone https://github.com/znuzhg/znuzhgfw.git
cd znuzhgfw
pip install -r requirements.txt

🎯 Kullanım (CLI)
Basit tarama
znuzhgfw --url https://example.com

Derin tarama
znuzhgfw --url https://example.com --depth 2 --threads 10

Cookie ile tarama
znuzhgfw --url https://target.com --cookies "PHPSESSID=xx; token=yy"

Markdown / JSON raporu
znuzhgfw --url https://example.com --report-format md --out scan.md

🧬 Modül Yönetimi

Şu anda tüm modüller otomatik çalışır.
v0.4.0 ile:
--modules sqli,xss,headers gibi seçilebilir modüller aktif olacak.

🕶 Red-Team Rapor Arayüzü
Oluşturulan HTML raporu koyu tema + kırmızı neon çizgiler ile tasarlanmıştır.

Örnek:

mathematica
[ ZNUZHGFW ]
Red Team Style Web Vulnerability Scanner
Target: https://example.com
Generated: 2025-11-24

Security Headers → 5 LOW  
HTTP Methods → INFO  
Rate Limit → INFO  
...
⚠️ Yasal Uyarı (LEGAL NOTICE)
<div style="background:#200; padding:12px; border-left:4px solid #f00;">
Bu araç sadece:

🔹 Kendi sistemlerinizde

🔹 Yazılı izin aldığınız hedeflerde

🔹 Eğitim ve savunma amacıyla

kullanılmalıdır.

Yetkisiz kullanım suçtur.
Geliştirici, kötüye kullanım sonucunda doğabilecek hiçbir eylemden sorumlu değildir.

</div>
📦 PyPI Metadata
Alan	Değer
Paket Adı	znuzhgfw
Versiyon	0.3.0
Python	>= 3.10
Lisans	MIT

🤝 Katkı Sağlama
Katkılar memnuniyetle karşılanır!
Lütfen şu dosyaları inceleyin:

CONTRIBUTING.md

CODE_OF_CONDUCT.md

SECURITY.md

🧩 Lisans
Bu proje MIT License ile lisanslanmıştır.

<div align="center">
🔥 ZNUZHGFW — Offensive Security style, Defensive purpose.
🜁 “Stay silent. Strike hard.”

</div> ```
