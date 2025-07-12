# 🔐 Encrypted ToDo App — Cross-Platform Secure Task Manager

Welcome to the **Encrypted ToDo** app — your **privacy-first**, **offline**, and **cross-platform** task manager. Built with _Electron_, _React_, _Express_, and _SQLite_, this app ensures that **your data stays on your device and encrypted** at all times.

## ✅ Features

*   🛡️ **End-to-End AES-256 Encryption**
*   🧠 **Programmable Logic Rules** (e.g., auto-delete old tasks, highlight by keyword)
*   🌓 **Dark Mode + Neoviolet Theme**
*   💻 **Offline-first**: Works without internet access
*   🔐 **Passphrase Protected**: Change anytime with brute-force protection
*   ⚡ **Fast & Lightweight**: No cloud, no tracking, no bloat
*   📦 **One-Click Cross-Platform Installers** for Windows, macOS, and Linux

## 🚀 Download & Install

Go to the latest release here:  
👉 [📥 Download from Releases](https://github.com/MRichard333/Encryped-Notetask-MRichard333/releases/tag/Crossplatform)

| Platform | File | Notes |
| --- | --- | --- |
| 🪟 Windows | `.exe` Comming soon!| Double-click to install |
| 🍎 macOS | `.dmg` Comming soon! | Drag to Applications |
| 🐧 Linux | `.AppImage` or `.deb` | Works on most distros, see below |

## 🐧 Linux Users

You can run the `.AppImage` directly or install via:

```
sudo dpkg -i Encrypted-ToDo.deb
sudo apt-get install -f
```

Or mark the `.AppImage` as executable and run it:

```
chmod +x Encrypted-ToDo.AppImage
./Encrypted-ToDo.AppImage
```

## 🧠 How it Works

*   Runs entirely locally using an encrypted SQLite database.
*   All tasks are encrypted using AES-256-CBC with a SHA-256 derived key.
*   You can define logic rules directly in the UI to customize behavior.
*   No internet connection is needed; no data is ever sent online.

## 👨‍💻 Tech Stack

*   Frontend: **React + TailwindCSS**
*   Backend: **Node.js + Express**
*   Database: **SQLite (encrypted)**
*   Security: **AES-256**, **bcrypt**, **rate limiting**
*   Packaging: **Electron Builder**

## 📖 Documentation

Coming soon! For now, check out the source code and feel free to open an issue if you have questions.

## ❤️ Contribute

*   [Open an Issue](https://github.com/MRichard333/Encryped-Notetask-MRichard333/issues)
*   Submit a Pull Request
*   Star ⭐ the repo if you find it useful!


**Built with love by [@MRichard333](https://github.com/MRichard333)**

## About

Made with ❤️ by [MRichard333](https://MRichard333.com) — supporting non-profit organizations through open-source software. Proudly developed in Canada.

© 2025 MRichard333
