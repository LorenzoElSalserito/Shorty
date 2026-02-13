# Shorty

![Shorty Logo](./Shorty.png)

> **URL Shortener self-hosted, senza database, privacy-first.**

Shorty è una soluzione leggera e potente per accorciare link, progettata per essere installata su qualsiasi hosting PHP in pochi secondi. Non richiede database SQL, utilizza un sistema di storage su file TXT veloce e gestisce automaticamente la scadenza dei link.

---

## ✨ Caratteristiche Principali

*   **Zero Database**: Nessun MySQL/PostgreSQL richiesto. Tutto è salvato su file di testo ottimizzati.
*   **Retention Automatica**: I link scadono e si autodistruggono dopo 7, 15, 30 o 90 giorni.
*   **Privacy First**: Nessun cookie di tracciamento, nessun analytics invasivo.
*   **Single Page Application**: Interfaccia utente moderna e reattiva basata su Vue.js.
*   **API JSON**: Backend separato utilizzabile anche via API.
*   **Open Source**: Rilasciato sotto licenza AGPLv3.

## 🚀 Installazione Rapida

1.  Scarica l'ultima versione (cartella `dist`).
2.  Carica i file sul tuo server (via FTP o SSH).
3.  Assicurati che la cartella `data` sia scrivibile (`chmod 755` o `777` a seconda dell'hosting).
4.  Apri il sito nel browser. Fatto!

## 🛠 Sviluppo Locale

### Prerequisiti
*   Node.js 20+
*   PHP 7.4+

### Comandi
```bash
# 1. Installa dipendenze
npm install

# 2. Avvia Backend (Terminal 1)
php -S localhost:8000 -t public

# 3. Avvia Frontend (Terminal 2)
npm run dev
```

### Build per Produzione
```bash
npm run build
```
Il contenuto della cartella `dist` è pronto per il deploy.

## 📄 Licenza
Questo progetto è distribuito sotto licenza **AGPLv3**. Vedi il file `LICENSE` per i dettagli.

## © Copyright
**Copyright © 2026 Lorenzo De Marco (Lorenzo DM)**
