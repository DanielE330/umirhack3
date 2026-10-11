import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LevelTag } from '../../components/common.jsx'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { CATALOG, CAT_LEVELS, HELP, formFromTemplate } from '../../lib/model.js'

function CatalogCard({ entry, used, onUse }) {
  const { t } = useLanguage()
  const showBanner = (b) => (b ? t('Баннер: {b}', { b: b.replace(/\r\n/g, ' ⏎ ') }) : t('Без баннера: порт молча ждёт данных'))
  return (
    <article className={'tcard lv-' + entry.level + (entry.planned ? ' planned' : '')}>
      <div className="thead">
        <span className="badge">{entry.icon}</span>
        <h3>{t(entry.name)}</h3>
        {entry.level === 'high' ? <span className="tag high" data-tip={t(HELP.high)}>High</span> : <LevelTag level={entry.level} />}
        {entry.planned && <span className="tag soon" data-tip={t('Агент пока не умеет такую ловушку. Это направление развития проекта.')}>{t('в разработке')}</span>}
      </div>
      {entry.services.length > 0 && (
        <div className="ports">
          {entry.services.map((x) => (
            <span key={x.port} data-tip={showBanner(x.banner)}>{x.port + '/' + (x.proto === 'banner' ? 'tcp' : x.proto)}</span>
          ))}
        </div>
      )}
      <dl className="tinfo">
        <dt>{t('Эмулирует')}</dt><dd>{t(entry.emulates)}</dd>
        <dt>{t('Собирает')}</dt><dd>{t(entry.collects)}</dd>
      </dl>
      {entry.note && <p className="tnote">⚠ {t(entry.note)}</p>}
      <div className="tfoot">
        <span className={'risk r-' + entry.level} data-tip={t('Насколько опасно держать такую ловушку: чем реалистичнее, тем больше атакующий может сделать внутри.')}>
          {t('Риск: {risk}', { risk: t(entry.risk).toLowerCase() })}
        </span>
        {used !== null && (
          <span className={'used' + (used ? ' on' : '')} data-tip={t('Сколько ловушек этого типа сейчас работает в контейнерах')}>
            {used ? t('запущено: {n}', { n: used }) : t('не запущена')}
          </span>
        )}
        {entry.planned
          ? <button className="ghost small" disabled data-tip={t('Появится в следующих версиях')}>{t('Скоро')}</button>
          : <button className="btn lg" data-tip={t('Открыть конструктор профиля, заполненный этим шаблоном')} onClick={() => onUse(entry)}>{t('Создать профиль')}</button>}
      </div>
    </article>
  )
}

export default function Traps() {
  const { traps, profileByName, setEditor } = useData()
  const { showToast } = useUi()
  const { t } = useLanguage()
  const navigate = useNavigate()
  const [level, setLevel] = useState('')
  const [query, setQuery] = useState('')

  // каталог короткий, поэтому фильтруем на каждом рендере: так поиск видит текущий язык
  const q = query.trim().toLowerCase()
  const list = CATALOG.filter((e) => (!level || e.level === level) &&
    (!q || [t(e.name), e.icon, t(e.emulates), t(e.collects), ...e.services.map((x) => String(x.port))].join(' ').toLowerCase().includes(q)))

  // сколько развёрнутых ловушек слушают такой же сервис
  const usage = (entry) => {
    if (entry.planned || entry.custom) return null
    const want = entry.services.map((x) => x.proto + ':' + x.port)
    return traps.filter((tr) => ((profileByName(tr.profile) || {}).services || []).some((x) => want.includes(x.proto + ':' + x.port))).length
  }
  const useTemplate = (entry) => {
    setEditor({ editing: null, form: formFromTemplate(entry) })
    navigate('/profiles')
    showToast(t('Конструктор заполнен по шаблону «{name}» — проверьте и сохраните', { name: t(entry.name) }))
  }
  const ready = CATALOG.filter((e) => !e.planned).length

  return (
    <section>
      <div className="toolbar">
        <div className="chips" role="radiogroup" aria-label={t('Уровень')}>
          {CAT_LEVELS.map(([v, label]) => (
            <button key={v} type="button" role="radio" aria-checked={v === level} className={v === level ? 'on' : ''}
              data-tip={v ? t('Показать только уровень {label}', { label }) : t('Показать все уровни')} onClick={() => setLevel(v)}>
              {t(label)}
            </button>
          ))}
        </div>
        <input className="w-search" placeholder={t('Поиск: ftp, 22, mysql…')} aria-label={t('Поиск по каталогу')}
          data-tip={t('Поиск по названию, порту и описанию')} value={query} onChange={(e) => setQuery(e.target.value)} />
        <span className="spacer" />
        <span className="hint">{t('{ready} типов готово · {n} в разработке', { ready, n: CATALOG.length - ready })}</span>
      </div>
      <p className="lead">
        {t('Все ловушки, которые умеет запускать агент. Выберите тип и нажмите «Создать профиль» — конструктор заполнится готовыми портами, баннерами и приманками; останется сохранить и добавить ловушку в контейнер.')}
      </p>
      <div className="catalog">
        {list.length
          ? list.map((e) => <CatalogCard key={e.id} entry={e} used={usage(e)} onUse={useTemplate} />)
          : <div className="cnone">{t('Ничего не найдено')}</div>}
      </div>
    </section>
  )
}
