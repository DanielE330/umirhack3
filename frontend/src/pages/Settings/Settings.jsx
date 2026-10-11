import { useState } from 'react'
import { BookOpen, Languages, LayoutPanelLeft, LayoutPanelTop, Lightbulb, MoonStar, RotateCcw, Send } from 'lucide-react'
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
  const { user, refresh } = useAuth()
  const [theme, setTheme] = useState(getTheme)
  const switchTheme = (light) => {
    const next = light ? 'light' : 'dark'
    applyTheme(next)
    setTheme(next)
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
            <ArmedButton label={t('Отвязать')} armLabel={t('Точно отвязать?')} className="ghost danger" onConfirm={unlink}
              tip={t('Алерты и сброс пароля через Telegram перестанут работать')} />
          ) : (
            <button type="button" className="btn" onClick={() => openModal(t('Привязать Telegram'), <TelegramLinkModal />)}>
              {t('Привязать')}
            </button>
          )}
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
