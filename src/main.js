import { createApp } from 'vue'
import App from './App.vue'

import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap-icons/font/bootstrap-icons.css'
import './theme.css'

// Follow the OS colour scheme (Bootstrap 5.3 colour modes).
const media = window.matchMedia('(prefers-color-scheme: dark)')
const applyTheme = () => document.documentElement.setAttribute('data-bs-theme', media.matches ? 'dark' : 'light')
applyTheme()
media.addEventListener('change', applyTheme)

createApp(App).mount('#app')
