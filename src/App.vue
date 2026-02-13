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

    // Basic client-side validation
    if (!url.value.startsWith('http://') && !url.value.startsWith('https://')) {
      throw new Error("L'URL deve iniziare con http:// o https://")
    }

    const response = await fetch('api.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: url.value,
        ttl_days: ttl.value
      })
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
  <div class="container">
    <header>
      <h1>Shorty</h1>
      <p>URL Shortener semplice e sicuro</p>
    </header>

    <main>
      <div class="card">
        <div class="form-group">
          <label for="url">Incolla il tuo link lungo</label>
          <input
            id="url"
            v-model="url"
            type="url"
            placeholder="https://esempio.com/pagina-molto-lunga..."
            @keyup.enter="shorten"
          >
        </div>

        <div class="form-group">
          <label>Scadenza link</label>
          <div class="ttl-options">
            <button
              v-for="days in ttls"
              :key="days"
              :class="{ active: ttl === days }"
              @click="ttl = days"
            >
              {{ days }} giorni
            </button>
          </div>
        </div>

        <button class="btn-primary" @click="shorten" :disabled="loading">
          {{ loading ? 'Creazione in corso...' : 'Accorcia Link' }}
        </button>

        <div v-if="error" class="error-message">
          {{ error }}
        </div>

        <div v-if="result" class="result-area">
          <div class="short-url">
            <a :href="result.short_url" target="_blank">{{ result.short_url }}</a>
          </div>
          <button class="btn-copy" @click="copyToClipboard">
            {{ copied ? 'Copiato!' : 'Copia' }}
          </button>
          <div class="meta">
            Scade il: {{ new Date(result.expires_at).toLocaleDateString() }}
          </div>
        </div>
      </div>
    </main>

    <footer>
      <div class="links">
        <a href="LICENSE" target="_blank">Licenza AGPLv3</a>
        <span class="sep">•</span>
        <a href="https://github.com/tuo-repo/shorty" target="_blank">Codice Sorgente</a>
        <span class="sep">•</span>
        <span class="privacy">Nessun tracciamento personale</span>
      </div>
      <p class="copyright">&copy; {{ new Date().getFullYear() }} Shorty</p>
    </footer>
  </div>
</template>

<style scoped>
.container {
  max-width: 600px;
  margin: 0 auto;
  padding: 2rem 1rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #333;
}

header {
  text-align: center;
  margin-bottom: 2rem;
}

h1 {
  font-size: 2.5rem;
  margin: 0;
  color: #2c3e50;
}

p {
  color: #666;
}

.card {
  background: white;
  padding: 2rem;
  border-radius: 12px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 600;
  color: #2c3e50;
}

input[type="url"] {
  width: 100%;
  padding: 0.75rem;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  font-size: 1rem;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

input[type="url"]:focus {
  border-color: #42b983;
  outline: none;
}

.ttl-options {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.ttl-options button {
  flex: 1;
  padding: 0.5rem;
  border: 2px solid #e0e0e0;
  background: white;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.ttl-options button.active {
  border-color: #42b983;
  background: #e8f5e9;
  color: #2c3e50;
}

.btn-primary {
  width: 100%;
  padding: 1rem;
  background: #42b983;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1.1rem;
  font-weight: bold;
  cursor: pointer;
  transition: background 0.2s;
}

.btn-primary:hover:not(:disabled) {
  background: #3aa876;
}

.btn-primary:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.error-message {
  margin-top: 1rem;
  padding: 0.75rem;
  background: #ffebee;
  color: #c62828;
  border-radius: 6px;
  text-align: center;
}

.result-area {
  margin-top: 1.5rem;
  padding: 1rem;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e0e0e0;
  text-align: center;
}

.short-url {
  font-size: 1.25rem;
  margin-bottom: 1rem;
  word-break: break-all;
}

.short-url a {
  color: #42b983;
  text-decoration: none;
  font-weight: bold;
}

.btn-copy {
  padding: 0.5rem 1rem;
  background: #2c3e50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.meta {
  margin-top: 0.5rem;
  font-size: 0.8rem;
  color: #666;
}

footer {
  margin-top: 3rem;
  text-align: center;
  font-size: 0.9rem;
  color: #999;
}

.links a {
  color: #666;
  text-decoration: none;
}

.links a:hover {
  text-decoration: underline;
}

.sep {
  margin: 0 0.5rem;
}
</style>
