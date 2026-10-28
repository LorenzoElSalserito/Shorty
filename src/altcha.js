// Self-hosted ALTCHA widget: CSP-friendly build, workers bundled as local files.
import 'altcha/external'
import 'altcha/altcha.css'
import 'altcha/i18n/it'
import Pbkdf2Worker from 'altcha/workers/pbkdf2?worker'

globalThis.$altcha.algorithms.set('PBKDF2/SHA-256', () => new Pbkdf2Worker())
