// Same-origin calls to the protected internal endpoints (not a public API).
let csrf = null

const call = async (path, options = {}) => {
  let res
  try {
    res = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options })
  } catch {
    throw new Error('Connessione non riuscita. Controlla la rete e riprova.')
  }
  let data = {}
  try {
    data = await res.json()
  } catch {
    // keep empty body
  }
  if (data.csrf) csrf = data.csrf
  if (!res.ok) {
    const err = new Error(data.message || 'Si è verificato un errore. Riprova.')
    err.code = data.error
    throw err
  }
  return data
}

export const bootstrap = () => call('internal/bootstrap.php')

export const post = (path, body) => call(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...body, csrf }),
})
