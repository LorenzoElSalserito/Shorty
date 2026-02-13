# Manuale Operativo Shorty

Questo documento descrive come testare Shorty e come integrarlo in qualsiasi sito web esistente.

---

## 🧪 Piano di Test

### 1. Test Funzionali (Backend & Frontend)

#### A. Creazione Link
1.  **URL Valido**: Inserisci `https://example.com` e seleziona 7 giorni.
    *   *Risultato atteso*: Link corto generato (es. `http://localhost:8000/AbCdEf`).
2.  **URL Non Valido**: Inserisci `ftp://example.com` o `javascript:alert(1)`.
    *   *Risultato atteso*: Errore visualizzato "Schema non valido".
3.  **TTL Diverso**: Seleziona 90 giorni.
    *   *Risultato atteso*: Link generato con scadenza corretta nel JSON di risposta.

#### B. Redirect
1.  **Link Valido**: Apri il link corto generato nel browser.
    *   *Risultato atteso*: Redirect immediato a `https://example.com`.
2.  **Link Inesistente**: Apri `http://localhost:8000/NonEsiste`.
    *   *Risultato atteso*: Pagina 404 o messaggio "Link not found".
3.  **Link Scaduto (Simulazione)**:
    *   Modifica manualmente il file `data/index.txt` cambiando la data di scadenza a ieri.
    *   Prova ad aprire il link.
    *   *Risultato atteso*: Messaggio "Link expired" o 404.

#### C. Persistenza Dati
1.  **Verifica File**: Dopo aver creato un link, controlla la cartella `data/`.
    *   Deve esistere una sottocartella (es. `7d/`).
    *   Deve esistere un file con la data di oggi (es. `2026-05-20.txt`).
    *   Il file deve contenere il record del link.

### 2. Test di Carico (Opzionale)
1.  Esegui 100 richieste di creazione link in rapida successione (script bash o Postman Runner).
2.  Verifica che non ci siano errori 500 e che i file non siano corrotti.

---

## 🌐 Guida all'Integrazione su Qualsiasi Sito

Shorty è progettato per essere "drop-in", ovvero copiabile in una cartella e funzionante subito.

### Scenario A: Installazione in Sottocartella (Consigliato)
Vuoi che Shorty sia accessibile su `tuosito.com/shorty`.

1.  **Preparazione**:
    *   Esegui `npm run build` in locale.
    *   Prendi il contenuto della cartella `dist`.

2.  **Upload**:
    *   Crea una cartella `shorty` nella root del tuo sito (spesso `public_html` o `www`).
    *   Carica tutti i file di `dist` dentro `shorty`.

3.  **Configurazione**:
    *   Apri `shorty/config.php`.
    *   Imposta `'base_url' => 'https://tuosito.com/shorty'`.
    *   Assicurati che la cartella `shorty/data` (o dove hai deciso di metterla) abbia permessi di scrittura (755 o 777).

4.  **Verifica**:
    *   Vai su `https://tuosito.com/shorty`. Dovresti vedere l'interfaccia.

### Scenario B: Sottodominio Dedicato
Vuoi usare `s.tuosito.com`.

1.  **DNS**:
    *   Crea un record A o CNAME per `s.tuosito.com` che punti al tuo server.

2.  **Virtual Host / Server Block**:
    *   Configura il server web (Apache/Nginx) per servire la cartella dove caricherai Shorty quando viene richiesto `s.tuosito.com`.

3.  **Upload**:
    *   Carica il contenuto di `dist` nella root del sottodominio.

4.  **Configurazione**:
    *   In `config.php`, imposta `'base_url' => 'https://s.tuosito.com'`.

### Scenario C: Integrazione via Iframe (Avanzato)
Vuoi mostrare il form di Shorty dentro una pagina esistente del tuo sito (es. `tuosito.com/tools/url-shortener`).

1.  Installa Shorty come nello Scenario A (es. in `/shorty`).
2.  Nella tua pagina HTML, inserisci:
    ```html
    <iframe src="/shorty/index.html" width="100%" height="600px" frameborder="0"></iframe>
    ```
3.  Nota: Il redirect funzionerà comunque, ma l'utente vedrà l'interfaccia dentro il tuo layout.

---

## ⚠️ Risoluzione Problemi Comuni

*   **Errore 500 / Pagina Bianca**:
    *   Controlla i permessi della cartella `data`. Il server web (spesso utente `www-data`) deve poter scrivere.
    *   Verifica che la versione PHP sia >= 7.4.
*   **404 su API**:
    *   Se usi Nginx, assicurati di avere le regole di rewrite corrette per passare le richieste `.php` a PHP-FPM.
    *   Se usi Apache, assicurati che `mod_rewrite` sia attivo (se usato) o che i file `.php` siano eseguiti.
*   **CORS Error**:
    *   Se il frontend è su un dominio diverso dal backend, devi abilitare gli header CORS in `api.php`. (Di default Shorty assume stessa origine).
