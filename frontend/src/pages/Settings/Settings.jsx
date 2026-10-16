import { useEffect, useState } from 'react'
import { Bell, BookOpen, Languages, LayoutPanelLeft, LayoutPanelTop, Lightbulb, MoonStar, RotateCcw, Send, Sliders } from 'lucide-react'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { useLayout } from '../../context/layout.js'
import { useUi } from '../../context/ui.js'
import IdeaModal from '../../components/modals/IdeaModal.jsx'
import PasswordModal from '../../components/modals/PasswordModal.jsx'
import TelegramLinkModal from '../../components/modals/TelegramLinkModal.jsx'
import { ArmedButton, ToggleSwitch } from '../../components/common.jsx'
import { applyTheme, getTheme } from '../../lib/theme.js'
import { api } from '../../lib/api.js'
import './settings.css'

// Карточка настроек: иконка, заголовок, описание и контрол снизу
function SettingCard({ icon: Icon, title, desc, children }) {
  return (
    <section className="card setting-card">
      <header className="setting-head">
        <span className="setting-icon"><Icon size={18} strokeWidth={1.5} aria-hidden="true" /></span>
        <h3>{title}</h3>
      </header>
      <p className="setting-desc">{desc}</p>
      <div className="setting-control">{children}</div>
    </section>
  )
}

export default function Settings() {
  // свой домен документации: VITE_WIKI_URL=https://wiki.example.ru при сборке (по умолчанию — /wiki на этом же хосте)
  const WIKI_URL = import.meta.env.VITE_WIKI_URL || '/wiki'
  const { t, lang, setLang } = useLanguage()
  const { layout, setLayout } = useLayout()
  const { openModal, showToast } = useUi()
  const { user, can, refresh } = useAuth()
  const canManageSettings = can ? (can('settings.manage') || can('traps.manage') || user.role === 'admin') : true
  const [theme, setTheme] = useState(getTheme)
  const switchTheme = (light) => {
    const next = light ? 'light' : 'dark'
    applyTheme(next)
    setTheme(next)
  }


  // Привязка одной кнопкой: код заранее выдаёт центр, ссылка t.me/<бот>?start=<код> сама отправляет боту /start <код>.
  // Статус проверяем раз в 3 секунды — карточка сама переключится, когда бот подтвердит привязку.
  const [tg, setTg] = useState(null)
  useEffect(() => {
    if (user.telegramLinked) return undefined
    let alive = true
    const fresh = () => api('/api/auth/me/telegram/code', { method: 'POST', body: {} }).then((d) => alive && setTg(d)).catch(() => {})
    fresh()
    const renew = setInterval(fresh, 10 * 60 * 1000) // код живёт 15 минут
    const poll = setInterval(refresh, 3000)
    return () => {
      alive = false
      clearInterval(renew)
      clearInterval(poll)
    }
  }, [user.telegramLinked, refresh])
  const testTelegram = async () => {
    try {
      await api('/api/auth/me/telegram/test', { method: 'POST', body: {} })
      showToast(t('Тестовое сообщение отправлено — проверьте Telegram'))
    } catch (e) {
      showToast(e.message, true)
    }
  }
  const unlink = async () => {
    try {
      await api('/api/auth/me/telegram', { method: 'DELETE' })
      showToast(t('Telegram отвязан'))
    } catch (e) {
      showToast(e.message, true)
    }
    await refresh()
  }

  const [threshold, setThreshold] = useState(user.alertThreatThreshold ?? 60)
  useEffect(() => {
    if (user.alertThreatThreshold != null) {
      setThreshold(user.alertThreatThreshold)
    }
  }, [user.alertThreatThreshold])

  const saveThreshold = async (val) => {
    const nextVal = typeof val === 'number' ? val : threshold
    setThreshold(nextVal)
    try {
      await api('/api/auth/me/alert-threshold', {
        method: 'PATCH',
        body: { threshold: Number(nextVal) },
      })
      if (canManageSettings) {
        api('/api/settings/threat-threshold', {
          method: 'PUT',
          body: { threshold: Number(nextVal) },
        }).catch(() => {})
      }
      showToast(t('Порог алертов сохранён: {val}/100', { val: nextVal }))
      await refresh()
    } catch (e) {
      showToast(e.message, true)
    }
  }

  return (
    <section className="settings">
      <div className="page-title">
        <h2>{t('Настройки')}</h2>
        <p className="hint">{t('Язык, расположение навигации и учётная запись')}</p>
      </div>

      <div className="settings-grid">
        <SettingCard icon={Languages} title={t('Язык')} desc={t('Язык интерфейса. Выбор сохраняется в этом браузере.')}>
          <ToggleSwitch label={t('Английский язык интерфейса')} off="Русский" on="English" checked={lang === 'en'}
            onChange={(en) => setLang(en ? 'en' : 'ru')} />
        </SettingCard>

        <SettingCard icon={MoonStar} title={t('Тема')} desc={t('Тёмная «медовая» или светлая. Выбор сохраняется в этом браузере.')}>
          <ToggleSwitch label={t('Светлая тема')} off={t('Тёмная')} on={t('Светлая')} checked={theme === 'light'} onChange={switchTheme} />
        </SettingCard>

        <SettingCard icon={LayoutPanelTop} title={t('Расположение навигации')}
          desc={t('Сверху — как раньше, слева — боковая панель. Изменение применяется сразу.')}>
          <ToggleSwitch label={t('Навигация слева')} checked={layout === 'side'} onChange={(side) => setLayout(side ? 'side' : 'top')}
            off={<><LayoutPanelTop size={16} strokeWidth={1.6} aria-hidden="true" />{t('Сверху')}</>}
            on={<><LayoutPanelLeft size={16} strokeWidth={1.6} aria-hidden="true" />{t('Слева')}</>} />
        </SettingCard>

        <SettingCard icon={Send} title={t('Telegram')}
          desc={user.telegramLinked
            ? t('Привязан @{name}: сюда приходят алерты и коды сброса пароля.', { name: user.telegramUsername || '—' })
            : t('Привяжите Telegram: туда будут приходить алерты об атаках и код, если вы забудете пароль.')}>
          {user.telegramLinked ? (
            <div className="inline">
              <span className="tg-account" data-tip={t('Аккаунт Telegram, привязанный к вашей учётной записи')}>
                <Send size={14} strokeWidth={1.6} aria-hidden="true" />
                {user.telegramUsername ? `@${user.telegramUsername}` : t('без имени пользователя')}
              </span>
              <button type="button" className="btn" onClick={testTelegram}
                data-tip={t('Бот пришлёт вам тестовое сообщение — так проверяется связь')}>{t('Отправить тест в Telegram')}</button>
              <ArmedButton label={t('Отвязать')} armLabel={t('Точно отвязать?')} className="ghost danger" onConfirm={unlink}
                tip={t('Алерты и сброс пароля через Telegram перестанут работать')} />
            </div>
          ) : (
            <div className="inline">
              {tg && tg.link ? (
                <a className="btn" href={tg.link} target="_blank" rel="noopener noreferrer"
                  data-tip={t('Откроется бот: нажмите «Запустить» — привязка завершится сама')}>{t('Привязать в Telegram')}</a>
              ) : (
                <button type="button" className="btn" onClick={() => openModal(t('Привязать Telegram'), <TelegramLinkModal />)}>{t('Привязать')}</button>
              )}
              <button type="button" className="ghost" onClick={() => openModal(t('Привязать Telegram'), <TelegramLinkModal />)}
                data-tip={t('Показать код и скопировать его')}>{t('Код')}</button>
            </div>
          )}
        </SettingCard>

        <SettingCard icon={Bell} title={t('Порог алертов в Telegram (спам-скор)')}
          desc={t('Минимальный уровень угрозы (Threat Score 0–100), при котором бот присылает уведомление. Позволяет избавиться от Alert Fatigue.')}>
          <div className="threshold-container">
            <div className="threshold-slider-row">
              <input
                type="range"
                className="threshold-slider"
                min="0"
                max="100"
                step="5"
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                onMouseUp={() => saveThreshold(threshold)}
                onTouchEnd={() => saveThreshold(threshold)}
                aria-label={t('Порог алертов')}
              />
              <span className="threshold-val">{threshold} / 100</span>
            </div>
            <div className="threshold-meta">
              <span className={`threshold-badge ${
                threshold >= 85 ? 'critical' : threshold >= 70 ? 'high' : threshold >= 40 ? 'medium' : 'low'
              }`}>
                {threshold >= 85
                  ? t('Критический (RCE, деструктивные действия, утечки .env)')
                  : threshold >= 70
                  ? t('Высокий (атаки, эксплойты и брутфорс)')
                  : threshold >= 40
                  ? t('Средний (подозрительная активность, рекомендуется)')
                  : t('Низкий (все события, включая фоновый шум)')}
              </span>
            </div>
            <div className="threat-presets">
              {[
                { label: t('40 — Низкий'), val: 40 },
                { label: t('60 — Стандарт'), val: 60 },
                { label: t('75 — Высокий'), val: 75 },
                { label: t('90 — Критический'), val: 90 },
              ].map((p) => (
                <button
                  key={p.val}
                  type="button"
                  className={`threat-preset-btn ${threshold === p.val ? 'active' : ''}`}
                  onClick={() => saveThreshold(p.val)}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        </SettingCard>

        <SettingCard icon={RotateCcw} title={t('Сменить пароль')}
          desc={t('Смена пароля своей учётной записи. Нужен текущий пароль; другие сеансы будут завершены.')}>
          <button type="button" className="btn" onClick={() => openModal(t('Сменить пароль'), <PasswordModal />)}>
            {t('Сменить')}
          </button>
        </SettingCard>

        <SettingCard icon={Lightbulb} title={t('Предложить идею ловушки')}
          desc={t('Знаете тип ловушки, которого не хватает в каталоге? Опишите идею — она сохранится в центре.')}>
          <button type="button" className="ghost" onClick={() => openModal(t('Предложить идею ловушки'), <IdeaModal />)}>
            {t('Предложить')}
          </button>
        </SettingCard>

        <SettingCard icon={BookOpen} title={t('Документация')}
          desc={t('Полное руководство по использованию HoneyForge: настройка профилей, развёртывание ловушек, работа с событиями и IoC.')}>
          <a className="docs-link" href={WIKI_URL} target="_blank" rel="noopener noreferrer">
            <BookOpen size={18} strokeWidth={1.5} aria-hidden="true" />
            {t('Просмотреть документацию')}
          </a>
        </SettingCard>
      </div>
    </section>
  )
}
