import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './app/App.jsx'
import { getTheme } from './lib/theme.js'
import './styles/variables.css'
import './styles/global.css'
import './styles/layout.css'
import './styles/layout-top.css'
import './styles/layout-side.css'

// тема — до первой отрисовки, чтобы не мигала тёмная при выбранной светлой
document.documentElement.dataset.theme = getTheme()

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
