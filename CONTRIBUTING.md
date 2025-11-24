# Contributing to ZNUZHGFW

Thanks for your interest in contributing to **ZNUZHGFW – Web Vulnerability Scanner**!  
This project welcomes contributions from the community and aims to remain clean, secure, and easy to extend.

Whether you're fixing a bug, improving documentation, or adding a new scanner — every contribution helps.

---

## 💡 How to Contribute

### 1. Fork the repository

Click **“Fork”** on GitHub and clone your fork:

```sh
git clone https://github.com/<your-username>/znuzhgfw.git
cd znuzhgfw
2. Create a new branch
Branch name examples:

bash
Kodu kopyala
feature/add-ssti-scanner
bugfix/fix-lfi-detection
docs/update-readme
Create your own branch:

sh
Kodu kopyala
git checkout -b feature/my-feature
3. Make your changes
Add features or fix bugs

Improve documentation

Follow the existing coding style

Ensure scanners follow the Report API (report.add(...) keyword-only format)

4. Test your changes
Use the local package build:

sh
Kodu kopyala
pip install -r requirements.txt
pip install .
Run a sample scan:

sh
Kodu kopyala
znuzhgfw --url https://example.com
5. Commit your work
Use clear and descriptive commit messages:

sh
Kodu kopyala
git add .
git commit -m "Add new SSTI scanner"
6. Push and create a Pull Request
sh
Kodu kopyala
git push origin feature/my-feature
Go to GitHub → Your repository → “New Pull Request”

Describe:

What you changed

Why

How it was tested

We will review your PR as soon as possible.

🧩 Code Style
Use Python 3.10+ syntax

Keep scanners modular (one vulnerability type = one file)

Avoid external dependencies unless absolutely necessary

Document new scanners inside the README.md

🛡️ Security
If your contribution involves a security fix, please:

Mention it clearly in your PR

Avoid publicly sharing exploit details

Email responsible disclosures to: znuz@yaani.com

🙏 Thank You
Every contribution makes ZNUZHGFW better.
Your help is appreciated — welcome to the project!
