import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { iconFor } from '../../lib/model.js'
import { LevelTag } from '../common.jsx'

// Выбор профилей ловушек карточками. Профили с пересекающимися портами в одной машине недоступны.
export default function TrapPicker({ existing, selected, multi, onChange }) {
  const { profiles, portsOf } = useData()
  const { showToast } = useUi()

  const used = new Map()
  for (const t of existing) for (const port of portsOf(t.profile)) used.set(port, t.name)
  for (const name of selected) for (const port of portsOf(name)) used.set(port, name)

  return (
    <div className="picker">
      {profiles.map((p) => {
        const isSel = selected.includes(p.name)
        const clash = isSel ? null : portsOf(p.name).find((port) => used.has(port))
        const why = clash ? 'порт ' + clash + ' уже занят: ' + used.get(clash) : ''
        const click = () => {
          if (clash) return showToast('Нельзя: ' + why, true)
          if (isSel) onChange(selected.filter((n) => n !== p.name))
          else onChange(multi ? [...selected, p.name] : [p.name])
          return undefined
        }
        return (
          <button key={p.id ?? p.name} type="button" aria-pressed={isSel} onClick={click}
            className={'pcard' + (isSel ? ' sel' : '') + (clash ? ' off' : '')}>
            <span className="badge">{iconFor(p)}</span>
            <div><span className="pn">{p.name}</span> <LevelTag level={p.level} /></div>
            <div className="pd">{p.desc || 'Сервисов: ' + p.services.length}</div>
            <div className="ports">{p.services.map((s) => <span key={s.port}>{s.port + '/' + s.proto}</span>)}</div>
            {clash && <div className="why">{why}</div>}
          </button>
        )
      })}
    </div>
  )
}
