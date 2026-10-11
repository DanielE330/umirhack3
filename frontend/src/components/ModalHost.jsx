import { useEffect } from 'react'
import { X } from 'lucide-react'
import { useLanguage } from '../context/language.js'
import { useUi } from '../context/ui.js'

// Диалог и уведомление. Стоит внутри DataProvider: содержимое окна — обычные компоненты с доступом к данным.
export default function ModalHost() {
  const { modal, closeModal, toast } = useUi()
  const { t } = useLanguage()

  useEffect(() => {
    if (!modal) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') closeModal()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [modal, closeModal])

  return (
    <>
      {modal && (
        <div className="modal" onMouseDown={(e) => e.target === e.currentTarget && closeModal()}>
          <div className="sheet" role="dialog" aria-modal="true" aria-labelledby="modal-title">
            <div className="sheet-head">
              <h2 id="modal-title">{modal.title}</h2>
              <button className="icon-btn" aria-label={t('Закрыть')} data-tip={t('Закрыть (Esc)')} onClick={closeModal}>
                <X size={18} strokeWidth={1.5} aria-hidden="true" />
              </button>
            </div>
            <div>{modal.content}</div>
          </div>
        </div>
      )}
      {toast && (
        <div key={toast.id} className={'toast' + (toast.bad ? ' bad' : '')} role="status" aria-live="polite">
          {toast.msg}
        </div>
      )}
    </>
  )
}
