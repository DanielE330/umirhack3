import { useMemo } from 'react'
import AddTrapModal from '../components/modals/AddTrapModal.jsx'
import AgentDeployModal from '../components/modals/AgentDeployModal.jsx'
import ContainerSettingsModal from '../components/modals/ContainerSettingsModal.jsx'
import EventModal from '../components/modals/EventModal.jsx'
import NewContainerModal from '../components/modals/NewContainerModal.jsx'
import PveInfoModal from '../components/modals/PveInfoModal.jsx'
import TrapModal from '../components/modals/TrapModal.jsx'
import { useUi } from '../context/ui.js'
import { TYPE_INFO } from '../lib/model.js'

// Открытие модальных окон панели. Окна принимают id и берут живые данные из контекста.
export function useModals() {
  const { openModal } = useUi()
  return useMemo(() => ({
    openNewContainer: () => openModal('Новый контейнер в Proxmox', <NewContainerModal />),
    openAddTrap: (c) => openModal('Добавить ловушку в «' + c.name + '»', <AddTrapModal vmid={c.vmid} />),
    openContainerSettings: (c) => openModal('Настройки «' + c.name + '»', <ContainerSettingsModal vmid={c.vmid} />),
    openPve: (c) => openModal('Proxmox: ' + TYPE_INFO[c.type].kind + ' ' + c.vmid + ' «' + c.name + '»', <PveInfoModal vmid={c.vmid} />),
    openTrap: (t) => openModal('Ловушка «' + t.name + '»', <TrapModal trapId={t.id} />),
    openDeploy: (t, artifact) => openModal('Агент для «' + t.name + '»', <AgentDeployModal trapId={t.id} artifact={artifact} />),
    openEvent: (ev) => openModal('Событие #' + ev.id, <EventModal ev={ev} />),
  }), [openModal])
}
