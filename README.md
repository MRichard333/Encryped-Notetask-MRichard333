# 🔐 Encrypted ToDo App — Cross-Platform Secure Task Manager

Welcome to the **Encrypted ToDo** app — your _privacy-first_, _offline_, and _cross-platform_ task manager. Built with **Electron**, **React**, **Express**, and **SQLite**, this app ensures that your data stays on your device and **encrypted** at all times.

## ✅ Features

*   🛡️ **End-to-End AES-256 Encryption**
*   🧠 **Programmable Logic Rules** (e.g., auto-delete old tasks, highlight by keyword)
*   🌗 **Dark Mode + Neoviolet Theme**
*   💻 **Offline-first**: Works without internet access
*   🔐 **Passphrase Protected**: Change anytime with brute-force protection
*   ⚡ **Fast & Lightweight**: No cloud, no tracking, no bloat
*   📦 **One-Click Cross-Platform Installers** for Windows, macOS, and Linux

![todoappopen](https://github.com/user-attachments/assets/d0e87411-c924-4b10-a2df-923b63e22ebe) 
![Todoapp1](https://github.com/user-attachments/assets/8d011cc6-285a-425e-a54f-0ca6cf9c24ea) 
![todoapp2](https://github.com/user-attachments/assets/6c169872-4fa8-49df-8b6d-5a3867e76456)

## 🚀 Download & Install

Go to the latest release here:

👉 **Linux** \[📥 Download from Releases\](https://github.com/MRichard333/Encryped-Notetask-MRichard333/releases/tag/Crossplatform)  
👉 **Windows** \[📥 Download from Releases\](https://github.com/MRichard333/Encryped-Notetask-MRichard333/releases/tag/Windows)

| Platform | File | Notes |
| --- | --- | --- |
| 🪟 Windows | .exe | Double-click to install |
| 🍎 macOS | .dmg (Coming Soon) | Drag to Applications |
| 🐧 Linux | .AppImage / .deb | Works on most distros (see below) |

## 🐧 Linux Users

You can now install Encrypted TaskManager via APT directly using our public repo:

```
curl -fsSL https://mrichard333.github.io/Encrypted-TaskManager/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/encrypted-taskmanager.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/encrypted-taskmanager.gpg] https://mrichard333.github.io/Encrypted-TaskManager stable main" | sudo tee /etc/apt/sources.list.d/encrypted-taskmanager.list

sudo apt update
sudo apt install encrypted-todo-app
```

Or run the `.AppImage` directly:

```
chmod +x Encrypted-ToDo.AppImage
./Encrypted-ToDo.AppImage
```

## 🧠 How it Works

*   Runs entirely locally using an encrypted SQLite database.
*   All tasks are encrypted using AES-256-GCM with a SHA-256 derived key.
*   You can define logic rules directly in the UI to customize behavior.
*   No internet connection is needed; no data is ever sent online.

![crypto1](https://github.com/user-attachments/assets/477b33ed-473e-4e5b-adc8-c5b0dffc90b0)

## 👨‍💻 Tech Stack

*   Frontend: **React + TailwindCSS**
*   Backend: **Node.js + Express**
*   Database: **SQLite (encrypted)**
*   Security: **AES-256**, **Argon2**, **rate limiting**
*   Packaging: **Electron Builder**

## 📖 Documentation

Coming soon! For now, check out the source code and feel free to open an issue if you have questions.

## ❤️ Contribute

*   [Open an Issue](https://github.com/MRichard333/Encryped-Notetask-MRichard333/issues)
*   Submit a Pull Request
*   Star ⭐ the repo if you find it useful!

**Built with love by [@MRichard333](https://github.com/MRichard333)**

## About

Made with ❤️ by [MRichard333](https://MRichard333.com) — A non-profit organization focused on Cybersecurity and Fraud-Prevention. Proudly developed in Canada.

© 2025 MRichard333
