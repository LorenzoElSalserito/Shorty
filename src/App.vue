<script setup>
import { computed, onMounted, ref, nextTick } from 'vue'
import './altcha.js'
import { bootstrap, post } from './api.js'
import AltchaBox from './components/AltchaBox.vue'

const TTL_LABELS = { '5h': '5 ore', '1d': '1 giorno', '7d': '7 giorni' }
const CATEGORY_LABELS = {
  phishing: 'Phishing (furto di credenziali)',
  malware: 'Malware o download pericoloso',
  scam: 'Truffa',
  impersonation: 'Si spaccia per qualcun altro',
  other: 'Altro contenuto dannoso',
}

const params = new URLSearchParams(window.location.search)
const reportCode = /^[A-Za-z0-9]{10}$/.test(params.get('r') || '') ? params.get('r') : null

const ready = ref(false)
const fatal = ref(null)
const config = ref({ ttls: ['5h', '1d', '7d'], quota: { max: 3, window_hours: 24 }, report_categories: [] })
const remaining = ref(null)
const lockdown = ref(false)

const url = ref('')
const ttl = ref('5h')
const category = ref('')
const busy = ref(false)
const error = ref(null)
const result = ref(null)
const reported = ref(null)
const copied = ref(false)
const altcha = ref(null)
const resultInput = ref(null)

const canSubmit = computed(() => !busy.value && !(lockdown.value && !reportCode))

onMounted(async () => {
  try {
    const data = await bootstrap()
    config.value = data
    ttl.value = data.default_ttl
    remaining.value = data.remaining
    lockdown.value = data.lockdown
  } catch (e) {
    fatal.value = e.message
  } finally {
    ready.value = true
  }
})

const fail = (e) => {
  error.value = e.message
  if (e.code === 'DAILY_QUOTA') remaining.value = 0
  if (e.code === 'SECURITY_LOCKDOWN') lockdown.value = true
}

const solve = async () => {
  const payload = await altcha.value.solve()
  if (!payload) throw new Error('Verifica anti-bot non completata. Riprova.')
  return payload
}

const shorten = async () => {
  error.value = null
  result.value = null
  copied.value = false
  const value = url.value.trim()
  if (!value) {
    error.value = 'Inserisci il link da accorciare.'
    return
  }
  if (!/^https:\/\//i.test(value)) {
    error.value = 'Il link deve iniziare con https://'
    return
  }
  busy.value = true
  try {
    const payload = await solve()
    const data = await post('internal/create.php', { url: value, ttl: ttl.value, altcha: payload })
    // The server returns a relative path: the absolute URL comes from the page itself,
    // so it is correct in a domain root, a subdomain or a subfolder.
    result.value = { ...data, short_url: new URL(data.short_path, window.location.href).toString() }
    remaining.value = data.remaining
    url.value = ''
    await nextTick()
    resultInput.value?.select()
  } catch (e) {
    fail(e)
  } finally {
    altcha.value?.reset()
    busy.value = false
  }
}

const report = async () => {
  error.value = null
  if (!category.value) {
    error.value = 'Scegli un motivo per la segnalazione.'
    return
  }
  busy.value = true
  try {
    const payload = await solve()
    const data = await post('internal/report-submit.php', { code: reportCode, category: category.value, altcha: payload })
    reported.value = data
  } catch (e) {
    fail(e)
  } finally {
    altcha.value?.reset()
    busy.value = false
  }
}

const copy = async () => {
  try {
    await navigator.clipboard.writeText(result.value.short_url)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    resultInput.value?.select()
  }
}

const formatDate = (ts) => new Date(ts * 1000).toLocaleString('it-IT', { dateStyle: 'medium', timeStyle: 'short' })
</script>

<template>
  <div class="min-vh-100 d-flex flex-column align-items-center py-4 py-md-5 px-3">
    <div class="shorty-card p-4 p-md-5 w-100" style="max-width: 640px">
      <header class="d-flex align-items-center gap-3 mb-4">
        <img :src="'static/logo-128.png'" alt="" width="56" height="56" class="rounded-3">
        <div>
          <h1 class="h3 mb-0">Shorty</h1>
          <p class="mb-0 text-muted-shorty">Link brevi a scadenza, con controlli anti-abuso</p>
        </div>
      </header>

      <div v-if="!ready" class="text-center py-5" role="status">
        <div class="spinner-border" aria-hidden="true"></div>
        <span class="visually-hidden">Caricamento…</span>
      </div>

      <div v-else-if="fatal" class="alert alert-danger" role="alert">
        <i class="bi bi-exclamation-triangle-fill me-2" aria-hidden="true"></i>{{ fatal }}
      </div>

      <!-- Abuse report -->
      <main v-else-if="reportCode">
        <h2 class="h5">Segnala un link</h2>
        <p class="text-muted-shorty">Link <code>{{ reportCode }}</code>. Le segnalazioni sono anonime: Shorty conserva solo identificatori pseudonimi.</p>
        <div v-if="reported" class="alert alert-success" role="status">
          <i class="bi bi-check-circle-fill me-2" aria-hidden="true"></i>
          Grazie, segnalazione registrata.
          <span v-if="reported.quarantined">Il link è stato messo in quarantena.</span>
        </div>
        <form v-else @submit.prevent="report" novalidate>
          <fieldset class="mb-3">
            <legend class="form-label fw-semibold fs-6">Motivo</legend>
            <div v-for="c in config.report_categories" :key="c" class="form-check">
              <input :id="'cat-' + c" v-model="category" class="form-check-input" type="radio" name="category" :value="c" :disabled="busy">
              <label class="form-check-label" :for="'cat-' + c">{{ CATEGORY_LABELS[c] || c }}</label>
            </div>
          </fieldset>
          <AltchaBox ref="altcha" action="report" class="mb-3" />
          <button type="submit" class="btn btn-shorty w-100" :disabled="!canSubmit">
            <span v-if="busy" class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>
            Invia segnalazione
          </button>
        </form>
        <div v-if="error" class="alert alert-danger mt-3 mb-0" role="alert">{{ error }}</div>
        <p class="mt-3 mb-0"><a href="./">Torna a Shorty</a></p>
      </main>

      <!-- Create -->
      <main v-else>
        <div v-if="lockdown" class="alert alert-warning" role="status">
          La creazione di nuovi link è sospesa per manutenzione di sicurezza.
        </div>
        <form @submit.prevent="shorten" novalidate>
          <div class="mb-3">
            <label for="url" class="form-label fw-semibold">Link da accorciare</label>
            <div class="input-group">
              <span class="input-group-text"><i class="bi bi-link-45deg" aria-hidden="true"></i></span>
              <input id="url" v-model="url" type="url" inputmode="url" autocomplete="off" class="form-control"
                placeholder="https://esempio.it/pagina" maxlength="2048" required :disabled="busy || lockdown"
                aria-describedby="url-help">
            </div>
            <div id="url-help" class="form-text text-muted-shorty">Solo indirizzi <strong>https://</strong> con nome di dominio.</div>
          </div>

          <fieldset class="mb-3">
            <legend class="form-label fw-semibold fs-6">Scadenza</legend>
            <div class="d-flex gap-2" role="radiogroup">
              <template v-for="t in config.ttls" :key="t">
                <input :id="'ttl-' + t" v-model="ttl" type="radio" class="btn-check" name="ttl" :value="t" :disabled="busy || lockdown">
                <label class="btn btn-ttl flex-fill" :for="'ttl-' + t">{{ TTL_LABELS[t] || t }}</label>
              </template>
            </div>
          </fieldset>

          <AltchaBox ref="altcha" action="create" class="mb-3" />

          <button type="submit" class="btn btn-shorty w-100" :disabled="!canSubmit">
            <span v-if="busy" class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>
            {{ busy ? 'Stiamo applicando i controlli anti-abuso…' : 'Accorcia link' }}
          </button>
        </form>

        <div v-if="error" class="alert alert-danger mt-3 mb-0 d-flex" role="alert">
          <i class="bi bi-exclamation-triangle-fill me-2" aria-hidden="true"></i>
          <div>{{ error }}</div>
        </div>

        <section v-if="result" class="mt-4 p-3 shorty-notice" aria-live="polite">
          <label for="short" class="form-label fw-semibold">Il tuo link breve</label>
          <div class="input-group">
            <input id="short" ref="resultInput" class="form-control" :value="result.short_url" readonly>
            <button class="btn btn-shorty" type="button" @click="copy">
              <i class="bi me-1" :class="copied ? 'bi-check2' : 'bi-clipboard'" aria-hidden="true"></i>{{ copied ? 'Copiato' : 'Copia' }}
            </button>
          </div>
          <p class="small mb-0 mt-2 text-muted-shorty">
            Scade il {{ formatDate(result.expires_at) }}.
            <span v-if="result.deduplicated">Avevi già creato questo link: ti restituiamo lo stesso.</span>
          </p>
        </section>

        <div class="mt-4 p-3 shorty-notice small">
          <p class="mb-1"><i class="bi bi-shield-check me-1" aria-hidden="true"></i>
            Per proteggere il servizio, ogni indirizzo può creare al massimo {{ config.quota.max }} link ogni {{ config.quota.window_hours }} ore.
            <strong v-if="remaining !== null">Disponibili ora: {{ remaining }}.</strong>
          </p>
          <p class="mb-0">Chi apre il link vede sempre la destinazione prima di uscire da Shorty. Shorty non garantisce la sicurezza dei siti di destinazione e può bloccare link segnalati.</p>
        </div>
      </main>

      <footer class="mt-4 pt-3 border-top text-center small text-muted-shorty">
        <a href="LICENSE" class="link-secondary">Licenza AGPLv3</a>
        <span class="mx-2" aria-hidden="true">·</span>
        <a href="https://github.com/LorenzoElSalserito/Shorty" class="link-secondary" rel="noopener noreferrer">Codice sorgente</a>
        <p class="mb-0 mt-1">Nessun tracciamento, nessun servizio esterno. © Lorenzo DM</p>
      </footer>
    </div>
  </div>
</template>
