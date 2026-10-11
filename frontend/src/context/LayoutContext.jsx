import { useEffect, useMemo, useState } from 'react'
import { LayoutContext } from './layout.js'

const readLayout = () => {
  try {
    return localStorage.getItem('layout') === 'side' ? 'side' : 'top'
  } catch {
    return 'top'
  }
}

// Расположение навигации: сохраняется в localStorage (ключ layout), переключается без перезагрузки
export default function LayoutProvider({ children }) {
  const [layout, setLayout] = useState(readLayout)

  useEffect(() => {
    try {
      localStorage.setItem('layout', layout)
    } catch {
      /* без сохранения выбор действует до перезагрузки */
    }
  }, [layout])

  const value = useMemo(() => ({ layout, setLayout }), [layout])
  return <LayoutContext.Provider value={value}>{children}</LayoutContext.Provider>
}
