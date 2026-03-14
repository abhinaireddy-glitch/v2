import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import CipherNest from './CipherNest.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <CipherNest />
  </StrictMode>,
)
