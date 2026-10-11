import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './app/App.jsx'
import './styles/variables.css'
import './styles/global.css'
import './styles/layout.css'
import './styles/layout-top.css'
import './styles/layout-side.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
