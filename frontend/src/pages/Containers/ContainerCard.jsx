import { Check, Info, RotateCw, Settings, Trash2, X } from 'lucide-react'
import { useData } from '../../context/data.js'
import { useNow } from '../../hooks/useNow.js'
import { useModals } from '../../hooks/useModals.jsx'
import { ArmedButton, HelpMark, LevelTag, StateBadge, Switch } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { HELP, STATES, TYPE_INFO, resParts, since } from '../../lib/model.js'

export default function ContainerCard({ c }) {
  const { trapsOf, portsOf, levelOf, toggleContainer, restartContainer, deleteContainer, removeTrap } = useData()
  const { openTrap, openAddTrap, openContainerSettings, openPve } = useModals()
  const now = useNow()
  const st = c.state
  const list = trapsOf(c.name)
  const t = TYPE_INFO[c.type]
  const seen = since(c.seen, now)
  const resHelp = ['Сколько ядер процессора выделено машине', 'Оперативная память машины', 'Размер диска машины (можно только увеличить)']
  const switchOff = st === 'creating' || st === 'failed' || st === 'starting'

  return (
    <div className={'ccard is-' + st}>
      <div className="chead">
        <h3>{c.name}</h3>
        <span className={'vmtag ' + c.type}
          data-tip={t.title + ' в Proxmox, нода ' + c.node + '.\n' + t.kind + ' ' + c.vmid + ' — номер машины (VMID) в Proxmox.\n' + t.desc}>
          {t.label} · {t.kind} {c.vmid}
        </span>
        <Switch on={c.status === 'running'} disabled={switchOff} onToggle={() => toggleContainer(c)}
          tip={c.status === 'running' ? 'Выключить машину (' + t.cli + ' shutdown)' : 'Включить машину (' + t.cli + ' start)'} />
      </div>

      <div className="cmeta">
        <StateBadge state={st} /> · IP <span className="m" data-tip="Адрес машины внутри изолированной сети DMZ">{c.host || '—'}</span> ·{' '}
        <span data-tip={HELP.seen}>на связи</span> <span>{seen}</span><HelpMark text={HELP.agent} />
      </div>

      <div className="cres">
        {resParts(c).map((r, i) => <span key={r} data-tip={resHelp[i]}>{r}</span>)}
        <span data-tip={HELP.dmz}>сеть {c.bridge} · DMZ</span>
        <span data-tip="Физический сервер Proxmox, на котором запущена машина">нода {c.node}</span>
      </div>

      {st === 'failed' && <div className="cnote warn">Proxmox не смог создать машину: {c.job.error}. Удалите её и создайте заново.</div>}
      {st === 'creating' && (
        <div className="cnote">
          Proxmox клонирует шаблон и настраивает {t.kind} {c.vmid}… Это занимает до пары минут.
          <div className="progress"><i /></div>
        </div>
      )}
      {st === 'waiting' && (
        <div className="cnote">
          {list.length ? 'Машина работает, но агенты ещё не вышли на связь. Откройте ловушку и нажмите «Подключить агента».' : 'Машина работает. Добавьте в неё ловушку.'}
        </div>
      )}
      {st === 'offline' && (
        <div className="cnote warn">
          Агент не выходит на связь (последний раз {seen}). Проверьте машину: выключите и снова включите её переключателем.
        </div>
      )}

      <div className={'titems' + (st === 'stopped' ? ' dim' : '')}>
        {list.length ? list.map((x) => (
          <div key={x.id} className="titem" data-tip={STATES[x.state].label + ' — нажмите, чтобы открыть'} {...clickable(() => openTrap(x))}>
            <span className={'dot ' + x.state} />
            <span className="nm">{x.name}</span>
            <LevelTag level={levelOf(x.profile)} />
            <span className="pf" data-tip="Порты, которые слушает ловушка">{portsOf(x.profile).join(', ')}</span>
            <span className="ev" data-tip="Сколько событий (подключений, попыток входа, команд) записала эта ловушка">{x.events}</span>
            <ArmedButton label={<X size={16} strokeWidth={1.5} aria-hidden="true" />} armLabel={<Check size={16} strokeWidth={1.5} aria-hidden="true" />}
              aria-label="Убрать" className="icon-btn" tip="Убрать ловушку из контейнера (нажмите дважды)" onConfirm={() => removeTrap(x)} />
          </div>
        )) : <div className="cnone">Пока пусто. Нажмите «+ Добавить ловушку».</div>}
      </div>

      <div className="cfoot">
        <button className="btn small" data-tip="Запустить в этой машине ещё одну ловушку. Агент поднимет её при ближайшем опросе центра." onClick={() => openAddTrap(c)}>+ Добавить ловушку</button>
        <span className="cicons">
          <button className="icon-btn" aria-label="Настройки" data-tip="Имя, IP, ресурсы машины и список её ловушек" onClick={() => openContainerSettings(c)}>
            <Settings size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>
          <button className="icon-btn" aria-label="Информация о машине" data-tip="Информация о машине: что делает центр и эквивалентные команды Proxmox" onClick={() => openPve(c)}>
            <Info size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>
          <button className="icon-btn" aria-label="Перезапустить машину" data-tip={'Перезапустить машину (' + t.cli + ' reboot ' + c.vmid + '). Агент снова выйдет на связь через несколько секунд.'} onClick={() => restartContainer(c)}>
            <RotateCw size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>
          <ArmedButton label={<Trash2 size={16} strokeWidth={1.5} aria-hidden="true" />} armLabel={<Check size={16} strokeWidth={1.5} aria-hidden="true" />}
            aria-label="Удалить машину" className="icon-btn danger" tip="Удалить машину вместе со всеми ловушками (нажмите дважды)" onConfirm={() => deleteContainer(c)} />
        </span>
      </div>
    </div>
  )
}
