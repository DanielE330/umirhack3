import { ArrowLeft } from 'lucide-react'
import { useLanguage } from '../../context/language.js'
// Текст руководства: frontend/WIKI.md, подставляется при сборке (Vite ?raw)
import wikiSource from '../../../WIKI.md?raw'
import Markdown from './markdown.jsx'
import './wiki.css'

// Страница документации /wiki. Открывается отдельно (новая вкладка) и не требует входа.
// Когда wiki будет на отдельном хосте, этот файл и ссылка в Настройках заменяются, сам текст не меняется.
export default function Wiki() {
  const { t } = useLanguage()
  return (
    <div className="wiki">
      <div className="wiki-head">
        <a className="wiki-back" href="/#/containers">
          <ArrowLeft size={16} strokeWidth={1.5} aria-hidden="true" />
          {t('В HoneyForge')}
        </a>
        <span className="wiki-title">{t('Документация')}</span>
      </div>
      <article className="wiki-body">
        <Markdown source={wikiSource} />
      </article>
    </div>
  )
}
