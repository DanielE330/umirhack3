import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LevelTag } from '../../components/common.jsx'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { CATALOG, CAT_LEVELS, HELP, formFromTemplate } from '../../lib/model.js'

const showBanner = (b) => (b ? 'Баннер: ' + b.replace(/\r\n/g, ' ⏎ ') : 'Без баннера: порт молча ждёт данных')

function CatalogCard({ entry, used, onUse }) {
  return (
    <article className={'tcard lv-' + entry.level + (entry.planned ? ' planned' : '')}>
      <div className="thead">
        <span className="badge">{entry.icon}</span>
        <h3>{entry.name}</h3>
        {entry.level === 'high' ? <span className="tag high" data-tip={HELP.high}>High</span> : <LevelTag level={entry.level} />}
        {entry.planned && <span className="tag soon" data-tip="Агент пока не умеет такую ловушку. Это направление развития проекта.">в разработке</span>}
      </div>
      {entry.services.length > 0 && (
        <div className="ports">
          {entry.services.map((x) => (
            <span key={x.port} data-tip={showBanner(x.banner)}>{x.port + '/' + (x.proto === 'banner' ? 'tcp' : x.proto)}</span>
          ))}
        </div>
      )}
      <dl className="tinfo">
        <dt>Эмулирует</dt><dd>{entry.emulates}</dd>
        <dt>Собирает</dt><dd>{entry.collects}</dd>
      </dl>
      {entry.note && <p className="tnote">⚠ {entry.note}</p>}
      <div className="tfoot">
        <span className={'risk r-' + entry.level} data-tip="Насколько опасно держать такую ловушку: чем реалистичнее, тем больше атакующий может сделать внутри.">
          Риск: {entry.risk.toLowerCase()}
        </span>
        {used !== null && (
          <span className={'used' + (used ? ' on' : '')} data-tip="Сколько ловушек этого типа сейчас работает в контейнерах">
            {used ? 'запущено: ' + used : 'не запущена'}
          </span>
        )}
        {entry.planned
          ? <button className="ghost small" disabled data-tip="Появится в следующих версиях">Скоро</button>
          : <button className="btn lg" data-tip="Открыть конструктор профиля, заполненный этим шаблоном" onClick={() => onUse(entry)}>Создать профиль</button>}
      </div>
    </article>
  )
}

export default function Traps() {
  const { traps, profileByName, setEditor } = useData()
  const { showToast } = useUi()
  const navigate = useNavigate()
  const [level, setLevel] = useState('')
  const [query, setQuery] = useState('')

  const list = useMemo(() => {
    const q = query.trim().toLowerCase()
    return CATALOG.filter((e) => (!level || e.level === level) &&
      (!q || [e.name, e.icon, e.emulates, e.collects, ...e.services.map((x) => String(x.port))].join(' ').toLowerCase().includes(q)))
  }, [level, query])

  // сколько развёрнутых ловушек слушают такой же сервис
  const usage = (entry) => {
    if (entry.planned || entry.custom) return null
    const want = entry.services.map((x) => x.proto + ':' + x.port)
    return traps.filter((t) => ((profileByName(t.profile) || {}).services || []).some((x) => want.includes(x.proto + ':' + x.port))).length
  }
  const useTemplate = (entry) => {
    setEditor({ editing: null, form: formFromTemplate(entry) })
    navigate('/profiles')
    showToast('Конструктор заполнен по шаблону «' + entry.name + '» — проверьте и сохраните')
  }
  const ready = CATALOG.filter((e) => !e.planned).length

  return (
    <section>
      <div className="toolbar">
        <div className="chips" role="radiogroup" aria-label="Уровень">
          {CAT_LEVELS.map(([v, label]) => (
            <button key={v} type="button" role="radio" aria-checked={v === level} className={v === level ? 'on' : ''}
              data-tip={v ? 'Показать только уровень ' + label : 'Показать все уровни'} onClick={() => setLevel(v)}>
              {label}
            </button>
          ))}
        </div>
        <input className="w-search" placeholder="Поиск: ftp, 22, mysql…" aria-label="Поиск по каталогу"
          data-tip="Поиск по названию, порту и описанию" value={query} onChange={(e) => setQuery(e.target.value)} />
        <span className="spacer" />
        <span className="hint">{ready} типов готово · {CATALOG.length - ready} в разработке</span>
      </div>
      <p className="lead">
        Все ловушки, которые умеет запускать агент. Выберите тип и нажмите «Создать профиль» — конструктор заполнится готовыми
        портами, баннерами и приманками; останется сохранить и добавить ловушку в контейнер.
      </p>
      <div className="catalog">
        {list.length
          ? list.map((e) => <CatalogCard key={e.id} entry={e} used={usage(e)} onUse={useTemplate} />)
          : <div className="cnone">Ничего не найдено</div>}
      </div>
    </section>
  )
}
