<script setup>
import { ref } from 'vue'

const url = ref('')
const ttl = ref(7)
const result = ref(null)
const error = ref(null)
const loading = ref(false)
const copied = ref(false)

const ttls = [7, 15, 30, 90]

const shorten = async () => {
  error.value = null
  result.value = null
  loading.value = true
  copied.value = false

  try {
    if (!url.value) throw new Error("Inserisci un URL")

    if (!url.value.startsWith('http://') && !url.value.startsWith('https://')) {
      throw new Error("L'URL deve iniziare con http:// o https://")
    }

    const response = await fetch('api.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.value, ttl_days: ttl.value })
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(data.message || "Errore durante la creazione del link")
    }

    result.value = data
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

const copyToClipboard = async () => {
  if (!result.value) return
  try {
    await navigator.clipboard.writeText(result.value.short_url)
    copied.value = true
    setTimeout(() => copied.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy', err)
  }
}
</script>

<template>
  <div class="container-fluid min-vh-100 d-flex flex-column justify-content-center align-items-center bg-gradient-custom position-relative">

    <!-- Splash Screen Overlay -->
    <div v-if="loading" class="splash-screen d-flex flex-column justify-content-center align-items-center">
      <div class="spinner-grow text-light mb-3" style="width: 3rem; height: 3rem;" role="status">
        <span class="visually-hidden">Loading...</span>
      </div>
      <h2 class="text-white fw-bold animate-pulse">Generazione Short Link...</h2>
      <p class="text-white-50">Stiamo preparando il tuo link sicuro</p>
    </div>

    <div class="card shadow-lg p-4 rounded-4" style="max-width: 600px; width: 100%; background: rgba(255, 255, 255, 0.95);">
      <header class="text-center mb-4">
        <img src="/Shorty.png" alt="Shorty Logo" class="img-fluid mb-3" style="max-height: 80px;">
        <h1 class="h2 text-navy">Shorty</h1>
        <p class="text-muted">URL Shortener semplice e sicuro</p>
      </header>

      <main>
        <div class="mb-3">
          <label for="url" class="form-label fw-bold text-navy">Incolla il tuo link lungo</label>
          <div class="input-group">
            <span class="input-group-text bg-white border-end-0"><i class="bi bi-link-45deg"></i></span>
            <input
              id="url"
              v-model="url"
              type="url"
              class="form-control border-start-0 ps-0"
              placeholder="https://esempio.com/pagina-molto-lunga..."
              @keyup.enter="shorten"
              :disabled="loading"
            >
          </div>
        </div>

        <div class="mb-4">
          <label class="form-label fw-bold text-navy">Scadenza link</label>
          <div class="d-flex gap-2 flex-wrap">
            <button
              v-for="days in ttls"
              :key="days"
              type="button"
              class="btn flex-grow-1"
              :class="ttl === days ? 'btn-navy' : 'btn-outline-secondary'"
              @click="ttl = days"
              :disabled="loading"
            >
              {{ days }} giorni
            </button>
          </div>
        </div>

        <button class="btn-navy w-100 py-2 mb-3 rounded-3 fw-bold shadow-sm" @click="shorten" :disabled="loading">
          Accorcia Link
        </button>

        <div v-if="error" class="alert alert-danger mt-3 d-flex align-items-center">
          <i class="bi bi-exclamation-triangle-fill me-2"></i>
          <div>{{ error }}</div>
        </div>

        <div v-if="result" class="mt-4 p-3 bg-light rounded-3 border border-success-subtle fade-in">
          <label class="form-label fw-bold text-success">Il tuo Short Link è pronto!</label>
          <div class="input-group mb-2">
            <input type="text" class="form-control bg-white" :value="result.short_url" readonly>
            <button class="btn btn-outline-primary" type="button" @click="copyToClipboard">
              {{ copied ? 'Copiato!' : 'Copia' }}
            </button>
          </div>
          <div class="small text-muted text-center">
            Scade il: {{ new Date(result.expires_at).toLocaleDateString() }}
          </div>
        </div>
      </main>

      <footer class="mt-5 text-center text-muted small">
        <div class="mb-2">
          <a href="LICENSE" target="_blank" class="text-decoration-none text-secondary">Licenza AGPLv3</a>
          <span class="mx-2">•</span>
          <a href="https://github.com/LorenzoElSalserito/Shorty" target="_blank" class="text-decoration-none text-secondary">Codice Sorgente</a>
        </div>
        <p class="mb-0">&copy; {{ new Date().getFullYear() }} Lorenzo DM - Shorty. Nessun tracciamento personale.</p>
      </footer>
    </div>
  </div>
</template>

<style>
/* Global styles override */
body {
  font-family: 'Segoe UI', Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Custom Colors */
.text-navy { color: #001f3f; }

.bg-gradient-custom {
  background: linear-gradient(135deg, #001f3f 0%, #77dd77 50%, #ff6961 100%);
  background-size: 200% 200%;
  animation: gradientBG 15s ease infinite;
}

@keyframes gradientBG {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

.btn-navy {
  background-color: #001f3f;
  color: white;
  border-color: #001f3f;
}
.btn-navy:hover {
  background-color: #003366;
  color: white;
}

.btn-pastel-green {
  background-color: #77dd77;
  border-color: #77dd77;
  color: #003366;
}
.btn-pastel-green:hover {
  background-color: #66cc66;
  color: #003366;
}

/* Splash Screen */
.splash-screen {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 31, 63, 0.85); /* Navy blue with opacity */
  backdrop-filter: blur(5px);
  z-index: 1050;
  border-radius: 0;
}

.animate-pulse {
  animation: pulse 1.5s infinite;
}

@keyframes pulse {
  0% { opacity: 0.6; }
  50% { opacity: 1; }
  100% { opacity: 0.6; }
}

.fade-in {
  animation: fadeIn 0.5s ease-in;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
