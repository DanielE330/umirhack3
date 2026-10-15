import { Check, History, Info, RotateCw, Settings, Trash2, X } from 'lucide-react'
import { useAuth } from '../../context/auth.js'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useNow } from '../../hooks/useNow.js'
import { useModals } from '../../hooks/useModals.jsx'
import { ArmedButton, HelpMark, LevelTag, StateBadge, Switch } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { HELP, STATES, TYPE_INFO, resParts, since } from '../../lib/model.js'

export default function ContainerCard({ c }) {
  const { trapsOf, portsOf, levelOf, toggleContainer, restartContainer, rollbackContainer, deleteContainer, removeTrap } = useData()
  const { openTrap, openAddTrap, openContainerSettings, openPve } = useModals()
  const { can } = useAuth()
  const { t } = useLanguage()
  const now = useNow()
  const st = c.state
  const list = trapsOf(c.name)
  const info = TYPE_INFO[c.type]
  const seen = since(c.seen, now)
  const resHelp = [
    t('Сколько ядер процессора выделено машине'),
    t('Оперативная память машины'),
    t('Размер диска машины (можно только увеличить)'),
  ]
  const switchOff = st === 'creating' || st === 'failed' || st === 'starting'

  return (
    <div className={'ccard is-' + st}>
      <div className="chead">
        <h3>{c.name}</h3>
        <span className={'vmtag ' + c.type}
          data-tip={t('{title} в Proxmox, нода {node}.\n{kind} {vmid} — номер машины (VMID) в Proxmox.\n{desc}', {
            title: t(info.title), node: c.node, kind: info.kind, vmid: c.vmid, desc: t(info.desc),
          })}>
          {info.label} · {info.kind} {c.vmid}
        </span>
        <Switch on={c.status === 'running'} disabled={switchOff || !can('machines.power')} onToggle={() => toggleContainer(c)}
          tip={c.status === 'running' ? t('Выключить машину ({cli} shutdown)', { cli: info.cli }) : t('Включить машину ({cli} start)', { cli: info.cli })} />
      </div>

      <div className="cmeta">
        <StateBadge state={st} /> · IP <span className="m" data-tip={t('Адрес машины внутри изолированной сети DMZ. Доступен по Tailscale (маршрут 10.20.0.0/24) без захода в домашнюю сеть')}>{c.host || '—'}</span> ·{' '}
        <span data-tip={t(HELP.seen)}>{t('на связи')}</span> <span>{seen}</span><HelpMark text={t(HELP.agent)} />
      </div>

      <div className="cres">
        {resParts(c).map((r, i) => <span key={i} data-tip={resHelp[i]}>{r}</span>)}
        <span data-tip={t(HELP.dmz)}>{t('сеть {bridge} · DMZ', { bridge: c.bridge })}</span>
        <span data-tip={t('Физический сервер Proxmox, на котором запущена машина')}>{t('нода {node}', { node: c.node })}</span>
      </div>

      {st === 'failed' && (
        <div className="cnote warn">{t('Proxmox не смог создать машину: {err}. Удалите её и создайте заново.', { err: c.job.error })}</div>
      )}
      {st === 'creating' && (
        <div className="cnote">
          {t('Proxmox клонирует шаблон и настраивает {kind} {vmid}… Это занимает до пары минут.', { kind: info.kind, vmid: c.vmid })}
          <div className="progress"><i /></div>
        </div>
      )}
      {st === 'waiting' && (
        <div className="cnote">
          {list.length
            ? t('Машина работает, агенты запускаются. Если через минуту статус не сменился — откройте ловушку и нажмите «Переустановить агента».')
            : t('Машина работает. Добавьте в неё ловушку — агент включится сам.')}
        </div>
      )}
      {st === 'offline' && (
        <div className="cnote warn">
          {t('Агент не выходит на связь (последний раз {seen}). Проверьте машину: выключите и снова включите её переключателем.', { seen })}
        </div>
      )}

      <div className={'titems' + (st === 'stopped' ? ' dim' : '')}>
        {list.length ? list.map((x) => (
          <div key={x.id} className="titem" data-tip={t('{state} — нажмите, чтобы открыть', { state: t(STATES[x.state].label) })} {...clickable(() => openTrap(x))}>
            <span className={'dot ' + x.state} />
            <span className="nm">{x.name}</span>
            <LevelTag level={levelOf(x.profile)} />
            <span className="pf" data-tip={t('Порты, которые слушает ловушка')}>{portsOf(x.profile).join(', ')}</span>
            <span className="ev" data-tip={t('Сколько событий (подключений, попыток входа, команд) записала эта ловушка')}>{x.events}</span>
            {can('traps.manage') && <ArmedButton label={<X size={16} strokeWidth={1.5} aria-hidden="true" />} armLabel={<Check size={16} strokeWidth={1.5} aria-hidden="true" />}
              aria-label={t('Убрать')} className="icon-btn" tip={t('Убрать ловушку из контейнера (нажмите дважды)')} onConfirm={() => removeTrap(x)} />}
          </div>
        )) : <div className="cnone">{t('Пока пусто. Нажмите «+ Добавить ловушку».')}</div>}
      </div>

      <div className="cfoot">
        {can('traps.manage') && <button className="btn small" data-tip={t('Запустить в этой машине ещё одну ловушку. Агент поднимет её при ближайшем опросе центра.')} onClick={() => openAddTrap(c)}>{t('+ Добавить ловушку')}</button>}
        <span className="cicons">
          {can('machines.manage') && <button className="icon-btn" aria-label={t('Настройки')} data-tip={t('Имя, IP, ресурсы машины и список её ловушек')} onClick={() => openContainerSettings(c)}>
            <Settings size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>}
          <button className="icon-btn" aria-label={t('Информация о машине')} data-tip={t('Информация о машине: что делает центр и эквивалентные команды Proxmox')} onClick={() => openPve(c)}>
            <Info size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>
          {can('machines.power') && <button className="icon-btn" aria-label={t('Перезапустить машину')}
            data-tip={t('Перезапустить машину ({cli} reboot {vmid}). Агент снова выйдет на связь через несколько секунд.', { cli: info.cli, vmid: c.vmid })}
            onClick={() => restartContainer(c)}>
            <RotateCw size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>}
          {can('machines.power') && <button className="icon-btn" aria-label={t('Откат к снимку Proxmox')}
            data-tip={t('Откатить машину {vmid} к чистому снимку Proxmox (High-Interaction baseline)', { vmid: c.vmid })}
            onClick={() => rollbackContainer(c)}>
            <History size={16} strokeWidth={1.5} aria-hidden="true" />
          </button>}
          {can('machines.manage') && <ArmedButton label={<Trash2 size={16} strokeWidth={1.5} aria-hidden="true" />} armLabel={<Check size={16} strokeWidth={1.5} aria-hidden="true" />}
            aria-label={t('Удалить машину')} className="icon-btn danger" tip={t('Удалить машину вместе со всеми ловушками (нажмите дважды)')} onConfirm={() => deleteContainer(c)} />}
        </span>
      </div>
    </div>
  )
}
