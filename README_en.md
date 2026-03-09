# Shorty

![Shorty Logo](./Shorty.png)

> **Self-hosted, database-free, privacy-first URL Shortener.**

Shorty is a lightweight and powerful solution for shortening links, designed to be installed on any PHP hosting in seconds. It requires no SQL database, uses a fast TXT file storage system, and automatically manages link expiration.

---

##  Key Features

*   **Zero Database**: No MySQL/PostgreSQL required. Everything is saved on optimized text files.
*   **Automatic Retention**: Links expire and self-destruct after 7, 15, 30, or 90 days.
*   **Privacy First**: No tracking cookies, no invasive analytics.
*   **Single Page Application**: Modern and reactive user interface based on Vue.js.
*   **JSON API**: Separate backend usable also via API.
*   **Open Source**: Released under AGPLv3 license.

##  Quick Installation

1.  Download the latest version (`dist` folder).
2.  Upload files to your server (via FTP or SSH).
3.  Ensure the `data` folder is writable (`chmod 755` or `777` depending on hosting).
4.  Open the site in the browser. Done!

##  Local Development

### Prerequisites
*   Node.js 20+
*   PHP 7.4+

### Commands
```bash
# 1. Install dependencies
npm install

# 2. Start Backend (Terminal 1)
php -S localhost:8000 -t public

# 3. Start Frontend (Terminal 2)
npm run dev
```

### Build for Production
```bash
npm run build
```
The content of the `dist` folder is ready for deploy.

##  License
This project is distributed under the **AGPLv3** license. See the `LICENSE` file for details.

## © Copyright
**Copyright © 2026 Lorenzo De Marco (Lorenzo DM)**
