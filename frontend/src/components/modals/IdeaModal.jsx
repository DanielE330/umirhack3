import { useState } from 'react'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { Field } from '../common.jsx'

// Идея нового типа ловушки: сохраняется в центре, список видят все операторы
export default function IdeaModal() {
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const send = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api('/api/ideas', { method: 'POST', body: { title, description } })
    } catch (ex) {
      setBusy(false)
      return setErr(ex.message)
    }
    closeModal()
    return showToast(t('Спасибо! Идея сохранена'))
  }

  return (
    <form onSubmit={send}>
      <Field label="Что за ловушка">
        <input required minLength={3} maxLength={120} autoFocus placeholder={t('Например: поддельный RDP')} value={title} onChange={(e) => setTitle(e.target.value)} />
      </Field>
      <Field label="Описание">
        <textarea rows={5} maxLength={4000} placeholder={t('Какой сервис эмулировать, какие порты, что она должна собирать')}
          value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy}>{t('Отправить')}</button>
        <button type="button" className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </form>
  )
}
