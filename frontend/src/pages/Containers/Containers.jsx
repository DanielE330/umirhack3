import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import Select from '../../components/Select.jsx'
import { useAuth } from '../../context/auth.js'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { ORDER, STATES } from '../../lib/model.js'
import ContainerCard from './ContainerCard.jsx'

export default function Containers() {
  const { containers, traps, pickProfiles, cFilter, setCFilter, trapsOf, orchError } = useData()
  const { can } = useAuth()
  const { showToast } = useUi()
  const { openNewContainer } = useModals()
  const { t } = useLanguage()
  const navigate = useNavigate()

  const q = cFilter.q.trim().toLowerCase()
  const list = useMemo(
    () =>
      containers.filter((c) => {
        if (cFilter.status && c.state !== cFilter.status) return false
        if (!q) return true
        return [c.name, c.host, String(c.vmid), c.type, ...trapsOf(c.name).flatMap((tr) => [tr.name, tr.profile])].join(' ').toLowerCase().includes(q)
      }),
    [containers, cFilter.status, q, trapsOf],
  )
  const working = containers.filter((c) => c.state === 'online').length

  const add = () => {
    if (orchError) {
      showToast(t('Невозможно создать контейнер: Proxmox не подключён ({err})', { err: orchError }), true)
      return
    }
    if (!pickProfiles.length) {
      showToast(t('Сначала создайте профиль ловушки'), true)
      navigate('/profiles')
      return
    }
    openNewContainer()
  }

  return (
    <section>
      {orchError && (
        <div className="orch-offline-card">
          <div className="orch-offline-header">
            <b>{t('Гипервизор Proxmox не подключён')}</b>
            <span className="badge badge-warn">{t('Автономный режим')}</span>
          </div>
          <p className="orch-offline-desc">
            {t('Причина: {err}', { err: orchError })}
          </p>
          <p className="orch-offline-hint">
            {t('HoneyForge работает в автономном режиме: ловушки и агенты могут запускаться прямо на хосте или в Docker. Чтобы создавать изолированные виртуальные машины LXC/QEMU в Proxmox VE, настройте параметры доступа в infra/.env (PROXMOX_HOST, PROXMOX_TOKEN_NAME, PROXMOX_TOKEN_VALUE).')}
          </p>
        </div>
      )}
      <div className="toolbar">
        {can('machines.manage') && (
          <button className="btn" data-tip={t('Создать в Proxmox новую машину в изолированной сети и запустить в ней ловушки')} onClick={add}>
            {t('+ Новый контейнер')}
          </button>
        )}
        <input className="w-search" placeholder={t('Поиск по контейнерам и ловушкам…')} aria-label={t('Поиск')} value={cFilter.q}
          onChange={(e) => setCFilter((f) => ({ ...f, q: e.target.value }))} />
        <Select className="w-status" aria-label={t('Статус')} data-tip={t('Показать только машины в выбранном состоянии')} value={cFilter.status}
          options={[{ value: '', label: t('Все состояния') }, ...ORDER.map((k) => ({ value: k, label: t(STATES[k].label) }))]}
          onChange={(e) => setCFilter((f) => ({ ...f, status: e.target.value }))} />
        <span className="spacer" />
        <span className="hint">{t('{machines} машин · {traps} ловушек · работает: {working}', { machines: containers.length, traps: traps.length, working })}</span>
      </div>
      <div className="legend">
        {ORDER.map((k) => (
          <span key={k} data-tip={t(STATES[k].hint)}><span className={'dot ' + k} />{t(STATES[k].label)}</span>
        ))}
      </div>
      <div className="cgrid">
        {list.length
          ? list.map((c) => <ContainerCard key={c.id} c={c} />)
          : <div className="cnone">{orchError ? t('Машины недоступны — Proxmox оффлайн или не настроен') : (containers.length ? t('Ничего не найдено') : t('Контейнеров пока нет — создайте первый'))}</div>}
      </div>
    </section>
  )
}
