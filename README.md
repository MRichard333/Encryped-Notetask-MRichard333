# Encryped-Notetask-MRichard333
# Encrypted NoteTask — Secure & Local ToDo + Notes App 🔐

MIT License Node.js ≥ 14.x React ≥ 18.x

A **fully local, encrypted** ToDo and Notes app with programmable rules and passphrase-based encryption to keep your data secure. Built with React, Node.js, and SQLite.

## Features

*   AES-256-CBC encryption of all notes & todos, locked by your passphrase
*   Manage todos with urgency & reminders (reminders coming soon)
*   Create, update, delete todos securely
*   Change your passphrase securely without data loss
*   Dark mode and smooth UI transitions
*   Designed for local use, no cloud syncing
*   Simple programmable rule system for task highlighting
*   Open source and self-hosted, you control your data

## Demo

![Screenshot of the app](./screenshot.png)

## Getting Started

### Prerequisites

*   Node.js v14 or higher
*   npm or yarn
*   Git

### Installation

```
git clone https://github.com/MRichard333/Encryped-Notetask-MRichard333.git
cd Encryped-Notetask-MRichard333
npm install
cd client
npm install
```

### Running Locally

```
# Start backend server
node server/app.js

# In another terminal, start React frontend (dev mode)
cd client
npm start

# Then visit http://localhost:3000 in your browser
```

### Building for Production

```
cd client
npm run build
cd ..
node server/app.js

# Visit http://localhost:3001
```

## Usage

\- On first launch, **set your encryption passphrase** — this will secure your data.  
\- Use the intuitive UI to add, edit, and delete todos.  
\- Change your passphrase anytime via the settings menu.  
\- Your data is stored encrypted locally in an SQLite database.

## Contributing

Contributions and improvements are welcome! Please open issues or pull requests.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## About

Made with ❤️ by [MRichard333](https://MRichard333.com) — supporting non-profit organizations through open-source software. Proudly developed in Canada.

© 2025 MRichard333