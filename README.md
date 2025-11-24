# ZNUZHG Pentest Framework v0.2

> ONLY FOR AUTHORIZED SECURITY TESTING & EDUCATIONAL USE

ZNUZHG Pentest Framework, web uygulamalarını otomatik olarak taramak için
tasarlanmış modüler, genişletilebilir bir güvenlik tarayıcısıdır.

## Özellikler

- 🌐 Crawler (aynı domain içinde gezinti, depth kontrollü)
- 🧪 SQL Injection Testleri
  - Boolean-based
  - Error-based
  - Time-based (Blind)
- 💥 XSS Testleri
  - Reflected XSS
  - DOM-based XSS sink tespiti
- 📂 LFI / Path Traversal Testleri
- 🔁 Open Redirect Testleri
- 🧱 Security Header Analizi
- 🚦 Rate Limit Analizi
- 🛡️ WAF (Cloudflare, Sucuri vb.) Basit Tespiti
- 🧠 SSTI (Server-Side Template Injection) Basit Testleri
- 📜 CRLF Injection Denemeleri
- 🧭 HTTP Methods Analizi (OPTIONS, TRACE)
- 📁 Directory Bruteforce (basit wordlist ile)
- 🧵 Multi-threaded tarama
- 📝 Markdown + HTML rapor üretimi
- 📜 Ayrıntılı log dosyası

## Kurulum

```bash
git clone https://github.com/znuzhg/znuzhg_pentest_framework.git
cd znuzhg_pentest_framework
pip install -r requirements.txt

Kullanım
python3 main.py \
  --url "https://hedef-sistem.com/" \
  --depth 1 \
  --threads 5 \
  --cookies "PHPSESSID=xxx; token=yyy" \
  --modules all \
  --report-md report.md \
  --report-html report.html


Belirli modüllerle çalıştırmak için:

python3 main.py \
  --url "https://hedef-sistem.com/" \
  --modules "sqli,xss,headers"

Uyarı (Legal / Etik)

Bu framework yalnızca:

Kendi sistemlerinizde

Açıkça yazılı izin aldığınız hedeflerde

Eğitim ve savunma amaçlı

kullanılmalıdır.

İzinsiz sistemlere karşı kullanmak, hem etik değildir hem de hukuki sonuçlar doğurabilir.
Yazar, bu aracın kötüye kullanımından doğacak sonuçlardan sorumlu değildir.

Lisans

MIT
