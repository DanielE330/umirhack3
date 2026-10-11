import { Languages, LayoutPanelLeft, LayoutPanelTop, Lightbulb, RotateCcw } from 'lucide-react'
import { useLanguage } from '../../context/language.js'
import { useLayout } from '../../context/layout.js'
import { useUi } from '../../context/ui.js'
import IdeaModal from '../../components/modals/IdeaModal.jsx'
import PasswordModal from '../../components/modals/PasswordModal.jsx'
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
  const { t, lang, setLang } = useLanguage()
  const { layout, setLayout } = useLayout()
  const { openModal } = useUi()

  return (
    <section className="settings">
      <div className="page-title">
        <h2>{t('Настройки')}</h2>
        <p className="hint">{t('Язык, расположение навигации и учётная запись')}</p>
      </div>

      <div className="settings-grid">
        <SettingCard icon={Languages} title={t('Язык')} desc={t('Язык интерфейса. Выбор сохраняется в этом браузере.')}>
          <div className="seg" role="radiogroup" aria-label={t('Язык')}>
            <button type="button" role="radio" aria-checked={lang === 'ru'} className={lang === 'ru' ? 'on' : ''} onClick={() => setLang('ru')}>
              <b>Русский</b>
            </button>
            <button type="button" role="radio" aria-checked={lang === 'en'} className={lang === 'en' ? 'on' : ''} onClick={() => setLang('en')}>
              <b>English</b>
            </button>
          </div>
        </SettingCard>

        <SettingCard icon={LayoutPanelTop} title={t('Расположение навигации')}
          desc={t('Сверху — как раньше, слева — боковая панель. Изменение применяется сразу.')}>
          <div className="seg" role="radiogroup" aria-label={t('Расположение навигации')}>
            <button type="button" role="radio" aria-checked={layout === 'top'} className={layout === 'top' ? 'on' : ''} onClick={() => setLayout('top')}>
              <b><LayoutPanelTop size={16} strokeWidth={1.5} aria-hidden="true" />{t('Сверху')}</b>
            </button>
            <button type="button" role="radio" aria-checked={layout === 'side'} className={layout === 'side' ? 'on' : ''} onClick={() => setLayout('side')}>
              <b><LayoutPanelLeft size={16} strokeWidth={1.5} aria-hidden="true" />{t('Слева')}</b>
            </button>
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
      </div>
    </section>
  )
}
