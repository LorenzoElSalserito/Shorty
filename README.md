# Shorty

![Shorty Logo](./Shorty.png)

> **Link brevi a scadenza, self-hosted, senza database, progettati per essere scomodi da abusare.**

Shorty 2 non è un redirector anonimo: è un *link disclosure gateway* a vita breve. Chi apre
un link breve vede sempre la destinazione e sceglie se proseguire. Si installa copiando una
cartella su qualsiasi hosting PHP.

---

## Caratteristiche

* **Nessun redirect automatico**: ogni link mostra una pagina intermedia con dominio e URL
  completo; si esce da Shorty solo con un clic (POST firmato, la destinazione è sempre
  ricaricata dal server).
* **Massimo 3 link per indirizzo IP ogni 24 ore** (finestra mobile), più limiti per rete,
  per dominio di destinazione e un tetto globale.
* **Scadenze brevi**: 5 ore (predefinita), 1 giorno, 7 giorni.
* **ALTCHA self-hosted**: proof-of-work open source incluso nel pacchetto, nessun CAPTCHA
  di terze parti, nessun cookie di tracciamento.
* **Policy URL rigida**: solo `https://` con nome di dominio; rifiutati IP, reti private,
  credenziali nell'URL, porte non standard, punycode, altri shortener, file eseguibili e
  archivi.
* **Denylist locale + feed FOSS** (Phishing.Database) compilato a ogni release; nessuna API
  esterna a runtime, nessun fetch delle destinazioni (niente SSRF).
* **Segnalazioni e quarantena automatica**, kill switch via FTP (`runtime/LOCKDOWN`).
* **Privacy**: gli IP non vengono mai salvati in chiaro; Shorty usa identificatori HMAC
  pseudonimi a scadenza. I log del web server restano fuori dal controllo dell'app.
* **Zero configurazione**: niente database, Composer, npm, cron o Docker sul server.
  Pulizia dei link scaduti automatica con il normale traffico.
* **Open Source**: AGPLv3. Solo componenti FOSS, elencati in `THIRD_PARTY_NOTICES.md`.

Non esiste un'API pubblica: gli endpoint interni richiedono sessione, token CSRF monouso,
ALTCHA valido e rispettano le quote.

## Installazione

Requisiti: PHP **8.3+** e HTTPS.

1. Scarica `shorty-dist.zip` (o costruiscilo con `npm run build:release`).
2. Copia il **contenuto** nella cartella del sito: la root di un dominio, di un sottodominio
   o una sottocartella (es. `public_html/shorty/`). Non c'è nulla da configurare.
3. Apri l'indirizzo nel browser. Shorty crea da solo `runtime/` e il proprio segreto.
   Se la cartella non è scrivibile da PHP mostra un errore e non accetta link.

I link hanno la forma `https://tuosito/?s=AbCdEf1234`, che funziona ovunque. Con Apache o
LiteSpeed funziona anche `https://tuosito/s/AbCdEf1234` (regole già incluse in `.htaccess`).

**Aggiornamento da Shorty 1**: copia il nuovo pacchetto sopra il vecchio. Al primo accesso
Shorty 2 elimina i vecchi link (`data/`, con IP in chiaro) e i file della v1. I vecchi
link breve rispondono `410 Gone`. Fai un backup offline prima, se ti serve per indagini.

Dettagli operativi, blocchi, lockdown e test manuali: [`OPS_MANUAL.md`](./OPS_MANUAL.md).

## Sviluppo

Prerequisiti: Node.js 20.19+ / 22.12+, PHP 8.3+, Composer.

```bash
npm install
composer install --no-dev      # ALTCHA PHP in public/lib/vendor
npm run psl:update             # snapshot Public Suffix List (già inclusa nel repo)
npm run feed:update            # feed anti-phishing compilato (non versionato)

# Backend (terminale 1) — SHORTY_DEV=1 abilita HTTP solo sul server di sviluppo PHP
SHORTY_DEV=1 php -S localhost:8000 -t public
# Frontend (terminale 2)
npm run dev
```

### Build e certificazione

```bash
npm run build:release          # crea dist/ + shorty-dist.zip e certifica l'artefatto
```

La certificazione gira sul pacchetto finale: test unitari, test di integrazione e abuso
(incluse 100 richieste parallele), Apache + mod_php reale in HTTPS con installazione in root,
sottodominio, sottocartella, senza `.htaccess` e upgrade dalla v1, test browser sotto Xvfb.
La build non cambia mai la versione.

## Licenza

Distribuito sotto licenza **AGPLv3**. Vedi `LICENSE` e `THIRD_PARTY_NOTICES.md`.

## © Copyright

**Copyright © 2026 Lorenzo De Marco (Lorenzo DM)**
