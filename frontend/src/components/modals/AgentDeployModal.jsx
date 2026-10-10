import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { TYPE_INFO } from '../../lib/model.js'

// Токен выпускается заново и показывается один раз, поэтому артефакт приходит готовым из TrapModal
export default function AgentDeployModal({ trapId, artifact }) {
  const { traps, containerByName } = useData()
  const { closeModal, showToast } = useUi()
  const t = traps.find((x) => x.id === trapId)
  const c = t ? containerByName(t.container) : null

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(artifact)
      showToast('Скопировано')
    } catch {
      showToast('Не удалось скопировать: выделите текст вручную', true)
    }
  }

  return (
    <>
      <p className="hint">
        Токен выпущен заново и показан один раз. Запустите агента внутри машины
        {c ? ' «' + c.name + '» (' + TYPE_INFO[c.type].kind + ' ' + c.vmid + ')' : ''}: код агента (папка agent/netsvc) и
        зависимости asyncssh, setproctitle должны лежать рядом.
      </p>
      <pre>{artifact}</pre>
      {c && (
        <>
          <h4>Через хост Proxmox</h4>
          <pre>{'pct exec ' + c.vmid + " -- sh -c 'cat > /opt/.netsvc.sh' < agent.sh\npct exec " + c.vmid + ' -- sh /opt/.netsvc.sh'}</pre>
        </>
      )}
      <div className="actions">
        <button className="btn" onClick={copy}>Копировать команду</button>
        <button className="ghost" onClick={closeModal}>Закрыть</button>
      </div>
    </>
  )
}
