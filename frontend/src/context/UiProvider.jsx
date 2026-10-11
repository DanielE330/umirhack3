import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { UiContext } from './ui.js'

// Уведомления и состояние модального окна. Сам диалог рисует ModalHost внутри DataProvider,
// чтобы содержимое окна видело живые данные центра.
export default function UiProvider({ children }) {
  const [toast, setToast] = useState(null)
  const [modal, setModal] = useState(null)
  const timer = useRef(0)

  const showToast = useCallback((msg, bad = false) => {
    clearTimeout(timer.current)
    setToast({ msg, bad, id: Date.now() })
    timer.current = setTimeout(() => setToast(null), 3200)
  }, [])
  useEffect(() => () => clearTimeout(timer.current), [])

  const openModal = useCallback((title, content, wide = false) => setModal({ title, content, wide }), [])
  const closeModal = useCallback(() => setModal(null), [])

  const value = useMemo(
    () => ({ toast, showToast, modal, openModal, closeModal }),
    [toast, showToast, modal, openModal, closeModal],
  )
  return <UiContext.Provider value={value}>{children}</UiContext.Provider>
}
