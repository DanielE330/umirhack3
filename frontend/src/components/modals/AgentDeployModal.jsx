import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { TYPE_INFO } from '../../lib/model.js'

// Токен выпускается заново и показывается один раз, поэтому артефакт приходит готовым из TrapModal
export default function AgentDeployModal({ trapId, artifact }) {
  const { traps, containerByName } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const tr = traps.find((x) => x.id === trapId)
  const c = tr ? containerByName(tr.container) : null

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(artifact)
      showToast(t('Скопировано'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }

  return (
    <>
      <p className="hint">
        {t('Токен выпущен заново и показан один раз. Запустите агента внутри машины{machine}: код агента (папка agent/netsvc) и зависимости asyncssh, setproctitle должны лежать рядом.', {
          machine: c ? t(' «{name}» ({kind} {vmid})', { name: c.name, kind: TYPE_INFO[c.type].kind, vmid: c.vmid }) : '',
        })}
      </p>
      <pre>{artifact}</pre>
      {c && (
        <>
          <h4>{t('Через хост Proxmox')}</h4>
          <pre>{'pct exec ' + c.vmid + " -- sh -c 'cat > /opt/.netsvc.sh' < agent.sh\npct exec " + c.vmid + ' -- sh /opt/.netsvc.sh'}</pre>
        </>
      )}
      <div className="actions">
        <button className="btn" onClick={copy}>{t('Копировать команду')}</button>
        <button className="ghost" onClick={closeModal}>{t('Закрыть')}</button>
      </div>
    </>
  )
}
