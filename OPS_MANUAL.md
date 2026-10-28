# Manuale operativo Shorty 2

Come installare, verificare e gestire Shorty in sicurezza. Non contiene modi per aggirare i
controlli: se un limite blocca un uso legittimo, alzalo in `lib/config/security.php` solo dopo
una review.

---

## 1. Installazione (copia-incolla)

Shorty è una cartella autosufficiente. Funziona identica in:

| Scenario | Dove copiare il contenuto del pacchetto | Indirizzo |
|---|---|---|
| Dominio dedicato | root del dominio (`public_html/`) | `https://shorty.it/` |
| Sottodominio | root del sottodominio (`s.tuosito.it` → la sua cartella) | `https://s.tuosito.it/` |
| Sottocartella | `public_html/shorty/` di un sito esistente | `https://tuosito.it/shorty/` |

1. Requisiti: PHP 8.3+, HTTPS attivo sul dominio. Nessuna estensione PHP aggiuntiva.
2. Copia **il contenuto** di `shorty-dist.zip` nella cartella (FTP o SSH). Non modificare file.
3. Visita l'indirizzo. Shorty crea `runtime/` (dati, segreto, lock) con le sue protezioni.
4. Se compare "Servizio non disponibile", PHP non può scrivere nella cartella: dai permessi
   di scrittura all'utente PHP sulla cartella di installazione (oppure crea `runtime/`
   scrivibile).

Non servono: database, Composer, npm, cron, Docker, modifiche a `php.ini` o al virtual host.
Il sottodominio richiede solo il record DNS e la cartella che il pannello di hosting associa
al sottodominio, come per qualsiasi sito.

**Link breve**: `https://…/?s=CODICE` funziona su qualsiasi server. Su Apache/LiteSpeed
`.htaccess` aggiunge `…/s/CODICE`. Su Nginx la forma `/s/CODICE` richiede una regola opzionale
(`location ~ ^/s/([A-Za-z0-9]{10})$ { rewrite ^ /index.php?s=$1 last; }`, prefissata dalla
sottocartella se serve): non fa parte della promessa zero-config.

**Nginx e cartelle interne**: `.htaccess` blocca `lib/` e `runtime/` su Apache. Su Nginx
ogni file dati è un `.php` che termina subito senza output, quindi i contenuti restano
protetti anche senza regole. Per difesa in profondità puoi aggiungere
`location ~ /(lib|runtime)/ { deny all; }`.

**Spostare `runtime/` fuori dalla document root** (consigliato se l'hosting lo consente):
imposta `runtime_dir` in `lib/config/security.php` su un percorso assoluto scrivibile.

### Aggiornamento da Shorty 1

Copia il pacchetto sopra la vecchia installazione. Al primo accesso Shorty 2 cancella in
automatico, un po' alla volta:

- `data/` (i link v1, con IP in chiaro);
- `config.php`, `lib/Shorty.php` e il vecchio `index.html` della v1.

I vecchi codici a 6 caratteri rispondono `410 Gone`, `api.php` risponde `410`.
Se ti serve un'analisi forense, scarica `data/` **prima** dell'upload e conservala offline.

### Aggiornamento di Shorty 2

Copia il nuovo pacchetto sopra il precedente. `runtime/` non è nel pacchetto: link, quote e
segreto restano. Conserva le tue modifiche a `lib/config/security.php` e
`lib/security/local/*.txt` (ricopiale dopo l'upload).

---

## 2. Pulizia automatica (purge)

Non serve cron. Ogni richiesta controlla con un solo `stat()` se l'ultima pulizia ha più di
5 minuti (`gc_interval`); in quel caso esegue un giro limitato (`gc_budget`, 200 file):

- link scaduti → cancellati, anche se nessuno li riapre;
- contatori di quota → cancellati dopo 30 ore;
- registro anti-replay ALTCHA → dopo la scadenza della challenge;
- segnalazioni → dopo 30 giorni; storia domini → dopo 90 giorni; metriche → dopo 90 giorni.

Un link scaduto aperto prima della pulizia risponde `410` e viene cancellato subito.
Su un sito senza visite la pulizia avviene alla visita successiva.

---

## 3. Kill switch (via FTP)

| File da creare | Effetto |
|---|---|
| `runtime/LOCKDOWN` | nessun nuovo link, nessuna challenge; i link esistenti restano consultabili |
| `runtime/FULL_LOCKDOWN` | in più nessuna uscita: tutti i link mostrano una pagina di blocco |

Il contenuto del file è indifferente (anche vuoto). Cancellalo per riaprire.
Regola: prima blocca, poi indaga.

---

## 4. Bloccare destinazioni e link

File in `lib/security/local/`, una voce per riga, `#` per i commenti. Una voce non valida
blocca la creazione di link (fail-closed) finché non la correggi.

| File | Voce | Effetto |
|---|---|---|
| `blocked-domains.txt` | `esempio.com` | blocca dominio e tutti i sottodomini, anche link già creati |
| `blocked-codes.txt` | `AbCdEf1234` | disattiva un link breve |
| `blocked-url-hashes.txt` | sha256 dell'URL canonico | blocca un URL preciso |
| `blocked-ips.txt` | `203.0.113.0/24` | rifiuta destinazioni che risolvono in quella rete |

I controlli si ripetono a ogni apertura e a ogni "Continua": un link bloccato dopo la
creazione va subito in stato `BLOCKED` (`410`).

Hash di un URL: `printf '%s' 'https://esempio.com/pagina' | sha256sum`.

## 5. Feed anti-phishing

Il pacchetto include un feed compilato da Phishing.Database (MIT) in
`lib/security/feeds/` (`METADATA.json` indica data e checksum). Il server non scarica mai
nulla. Per aggiornarlo: `npm run build:release -- --refresh-feed` sul computer di build, poi
carica la nuova cartella `lib/security/feeds/` (o l'intero pacchetto).

Nota: il feed elenca anche host molto abusati come `docs.google.com` e `sites.google.com`;
i link verso quegli host vengono rifiutati. È una scelta voluta (sicurezza prima della comodità).

Senza feed Shorty entra in modalità conservativa: nessun dominio diventa `TRUSTED_LOCAL`.

---

## 6. Abusi, quarantena e fiducia

- Ogni pagina intermedia ha "Segnala questo link" (categorie fisse, ALTCHA leggero).
- 1 segnalazione: solo flag. 2 da reti diverse e un segnale di rischio (dominio nuovo,
  piattaforma di hosting gratuito, feed assente): quarantena. 3 da reti diverse: quarantena.
- Un link in quarantena non porta più fuori da Shorty; il dominio diventa `SUSPICIOUS` e non
  accetta nuovi link.
- `TRUSTED_LOCAL` richiede almeno 7 giorni di storia, 3 reti distinte, nessuna segnalazione.
  Toglie solo il conto alla rovescia e alza la quota per dominio: ALTCHA, 3 link/IP/24h,
  pagina intermedia e denylist restano.

## 7. Metriche e riconoscimento abusi

`runtime/metrics/AAAA-MM-GG.php`: contatori giornalieri aggregati, senza identificatori
(scarica via FTP, il JSON è dopo la prima riga). Voci utili:

- `create_attempts`, `create_success`, `create_dedup`;
- `reject_daily_quota`, `reject_rate_limit` (molti → automazione in corso, valuta `LOCKDOWN`);
- `reject_altcha_invalid`, `reject_challenge_replay` (bot che riusano proof);
- `reject_<motivo>` della policy URL (`nested_shortener`, `threat_feed`, `denylist`,
  `risky_extension`, `dns_non_public`, …);
- `abuse_reports`, `quarantines`, `outbound_clicks`, `interstitial_views`.

`reject_security_lockdown` alto senza lockdown attivo = tetto globale giornaliero raggiunto
(`quota.global_links`, 100/24h): utile durante la riapertura controllata.

## 8. Purge completo

1. Crea `runtime/FULL_LOCKDOWN`.
2. Cancella `runtime/links/`, `runtime/dedup/`, `runtime/reports/`, `runtime/retention/`.
3. Per invalidare anche sessioni, token e identificatori pseudonimi: cancella tutto `runtime/`
   (verrà ricreato con un nuovo segreto).
4. Rimuovi `FULL_LOCKDOWN` (se hai cancellato tutto `runtime/`, non serve).

---

## 9. Verifica dopo il deploy (test manuali)

1. Home: si apre, mostra 5 ore / 1 giorno / 7 giorni e l'avviso "al massimo 3 link".
2. Crea un link verso `https://example.com/`: compare `…/?s=CODICE` dentro la tua cartella.
3. Apri il link: pagina "Stai lasciando Shorty", dominio e URL completo, "Continua" attivo dopo
   3 secondi, poi arrivi alla destinazione.
4. Rifiuti attesi: `http://example.com`, `https://127.0.0.1`, `https://bit.ly/x`,
   `https://example.com/file.exe`.
5. Quarto link dallo stesso IP entro 24 ore: "al massimo 3 link ogni 24 ore".
6. `https://…/runtime/secrets.php` e `https://…/lib/config/security.php`: pagina vuota o 403.
7. `https://…/api.php`: `410`.

La certificazione automatica (`npm run build:release`) esegue questi e molti altri controlli
sul pacchetto, incluso Apache reale in HTTPS nei tre scenari di installazione.

---

## 10. Calibrazione ALTCHA

I livelli sono in `lib/config/security.php` (`altcha.levels`, intervalli del contatore PBKDF2
con `cost` 1000). La suite e2e misura il tempo reale del widget con un solo worker e salva
`altcha-calibration.json`. Obiettivi: base 0,3–0,8 s su desktop, medio 1–2 s, alto 2–4 s.
Il livello sale automaticamente con i tentativi falliti dello stesso IP o della stessa rete.

## 11. Limiti noti (da non nascondere)

- Una persona può comunque creare fino a 3 link malevoli al giorno; una botnet usa più IP.
- Una destinazione lecita può diventare malevola dopo la creazione (mitigato da TTL brevi,
  ricontrollo a ogni apertura, segnalazioni).
- Il feed locale è aggiornato a ogni release, non in tempo reale.
- Il provider di hosting può registrare gli IP nei log del web server.
- Dietro un reverse proxy tutti i client appaiono con lo stesso IP: configura
  `trusted_proxies`, altrimenti la quota 3/24h vale per tutti insieme.
- Google può mantenere un avviso anche dopo la bonifica: la revisione è una decisione esterna.
