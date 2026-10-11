import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft } from 'lucide-react'
import { useLanguage } from '../../context/language.js'
// Текст руководства: frontend/WIKI.md, подставляется при сборке (Vite ?raw)
import wikiSource from '../../../WIKI.md?raw'
import Markdown from './markdown.jsx'
import { headings } from './toc.js'
import './wiki.css'

// Страница документации /wiki. Открывается отдельно (новая вкладка) и не требует входа.
// На собственном хосте wiki.<домен> показывается она же (см. main.jsx), «В HoneyForge» там скрыта.
export default function Wiki() {
  const { t } = useLanguage()
  const toc = useMemo(() => headings(wikiSource), [])
  const [active, setActive] = useState(toc[0] ? toc[0].id : '')
  const standalone = window.location.hostname.startsWith('wiki.')

  // подсветка раздела, который сейчас на экране
  useEffect(() => {
    const obs = new IntersectionObserver(
      (entries) => {
        const hit = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0]
        if (hit) setActive(hit.target.id)
      },
      { rootMargin: '-72px 0px -70% 0px' },
    )
    toc.forEach((h) => {
      const el = document.getElementById(h.id)
      if (el) obs.observe(el)
    })
    return () => obs.disconnect()
  }, [toc])

  // обычная #-ссылка сломала бы hash-роутер, поэтому скроллим сами
  const go = (id) => (e) => {
    e.preventDefault()
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' })
    setActive(id)
  }

  return (
    <div className="wiki">
      <div className="wiki-head">
        {!standalone && (
          <a className="wiki-back" href="/#/containers">
            <ArrowLeft size={16} strokeWidth={1.5} aria-hidden="true" />
            {t('В HoneyForge')}
          </a>
        )}
        <span className="wiki-title">{t('Документация')}</span>
      </div>
      <div className="wiki-layout">
        <nav className="wiki-toc" aria-label={t('Оглавление')}>
          <div className="wiki-toc-title">{t('Оглавление')}</div>
          <ul>
            {toc.map((h) => (
              <li key={h.id} className={'l' + h.level}>
                <a href={'#' + h.id} className={h.id === active ? 'on' : ''} onClick={go(h.id)}>{h.text}</a>
              </li>
            ))}
          </ul>
        </nav>
        <article className="wiki-body">
          <Markdown source={wikiSource} />
        </article>
      </div>
    </div>
  )
}
