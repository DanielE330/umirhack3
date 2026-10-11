import { useMemo } from 'react'
import AddTrapModal from '../components/modals/AddTrapModal.jsx'
import AgentDeployModal from '../components/modals/AgentDeployModal.jsx'
import ContainerSettingsModal from '../components/modals/ContainerSettingsModal.jsx'
import EventModal from '../components/modals/EventModal.jsx'
import NewContainerModal from '../components/modals/NewContainerModal.jsx'
import PveInfoModal from '../components/modals/PveInfoModal.jsx'
import TrapModal from '../components/modals/TrapModal.jsx'
import { useUi } from '../context/ui.js'
import { t } from '../i18n/translations.js'
import { TYPE_INFO } from '../lib/model.js'

// Открытие модальных окон панели. Окна принимают id и берут живые данные из контекста.
export function useModals() {
  const { openModal } = useUi()
  return useMemo(() => ({
    openNewContainer: () => openModal(t('Создать машину в Proxmox'), <NewContainerModal />, true),
    openAddTrap: (c) => openModal(t('Добавить ловушку в «{name}»', { name: c.name }), <AddTrapModal vmid={c.vmid} />),
    openContainerSettings: (c) => openModal(t('Настройки «{name}»', { name: c.name }), <ContainerSettingsModal vmid={c.vmid} />),
    openPve: (c) => openModal(t('Proxmox: {kind} {vmid} «{name}»', { kind: TYPE_INFO[c.type].kind, vmid: c.vmid, name: c.name }), <PveInfoModal vmid={c.vmid} />),
    openTrap: (tr) => openModal(t('Ловушка «{name}»', { name: tr.name }), <TrapModal trapId={tr.id} />),
    openDeploy: (tr, artifact) => openModal(t('Агент для «{name}»', { name: tr.name }), <AgentDeployModal trapId={tr.id} artifact={artifact} />),
    openEvent: (ev) => openModal(t('Событие #{id}', { id: ev.id }), <EventModal ev={ev} />),
  }), [openModal])
}
