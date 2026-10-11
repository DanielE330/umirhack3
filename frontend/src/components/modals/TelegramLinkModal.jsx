import { useEffect, useState } from 'react'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'

// Привязка Telegram: центр выдаёт одноразовый код, бот принимает его по ссылке t.me/<бот>?start=<код>
// или командой /start <код>. Окно само ждёт подтверждения от бота и закрывается.
export default function TelegramLinkModal() {
  const { refresh } = useAuth()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [link, setLink] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    let timer = 0
    const poll = async () => {
      try {
        const me = await api('/api/auth/me')
        if (me.telegram_linked) {
          await refresh()
          closeModal()
          showToast(t('Telegram привязан: @{name}', { name: me.telegram_username || '—' }))
          return
        }
      } catch {
        /* сеть моргнула — попробуем ещё раз */
      }
      if (alive) timer = setTimeout(poll, 3000)
    }
    api('/api/auth/me/telegram/code', { method: 'POST', body: {} })
      .then((d) => {
        if (!alive) return
        setLink(d)
        timer = setTimeout(poll, 3000)
      })
      .catch((e) => alive && setErr(e.message))
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [refresh, closeModal, showToast, t])

  if (err) return <div className="err" role="alert">{err}</div>
  if (!link) return <p className="hint">{t('Получаю код…')}</p>
  return (
    <>
      <p className="hint">
        {t('Откройте бота и отправьте ему код — окно закроется само, как только бот подтвердит привязку. Код действует 15 минут.')}
      </p>
      <pre className="tg-code">{link.code}</pre>
      {link.link ? (
        <p><a className="btn" href={link.link} target="_blank" rel="noopener noreferrer">{t('Открыть @{bot} в Telegram', { bot: link.bot_username })}</a></p>
      ) : (
        <p className="hint">{t('Имя бота не настроено в центре (TELEGRAM_BOT_USERNAME): найдите бота HoneyForge вручную.')}</p>
      )}
      <p className="hint">{t('Или отправьте боту команду:')} <code>/start {link.code}</code></p>
      <p className="hint">{t('Ждём подтверждения от бота…')}</p>
      <div className="actions">
        <button className="ghost" onClick={closeModal}>{t('Закрыть')}</button>
      </div>
    </>
  )
}
