import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { PVE, TYPE_INFO, pveCommands, resParts } from '../../lib/model.js'
import { Kv } from '../common.jsx'

export default function PveInfoModal({ vmid }) {
  const { containers, trapsOf } = useData()
  const { closeModal, showToast } = useUi()
  const c = containers.find((x) => x.vmid === vmid)
  if (!c) return <p className="hint">Машина уже удалена</p>
  const t = TYPE_INFO[c.type]
  const commands = pveCommands(c)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(commands)
      showToast('Скопировано')
    } catch {
      showToast('Не удалось скопировать: выделите текст вручную', true)
    }
  }

  return (
    <>
      <Kv rows={[
        ['Тип', t.label + ' — ' + t.title], ['VMID', c.vmid], ['Нода', c.node], ['Ресурсы', resParts(c).join(' · ')],
        ['Сеть', PVE.bridgeLabel], ['IP', c.host], ['Ловушки', trapsOf(c.name).map((x) => x.name).join(', ') || '—'],
      ]} />
      <h4>Что делает центр</h4>
      <ol className="steps">
        <li><b>Клонирование:</b> оркестратор через Proxmox API делает полный клон шаблона {PVE.templates[c.type] || '—'} в {t.kind} {c.vmid} на хранилище {PVE.storage}.</li>
        <li><b>Ресурсы и сеть:</b> {resParts(c).join(', ')}; интерфейс в {c.bridge} (DMZ) с адресом {c.host || 'из 10.20.0.0/24'}, без доступа в домашнюю сеть. Тег honeyforge: чужие машины оркестратор не трогает.</li>
        <li><b>Запуск:</b> машина стартует; агент в ней подключается к центру и поднимает ловушки (кнопка «Подключить агента» в окне ловушки).</li>
      </ol>
      <h4>Эквивалентные команды Proxmox (для справки и ручной отладки)</h4>
      <pre>{commands}</pre>
      <div className="actions">
        <button className="ghost" onClick={copy}>Копировать команды</button>
        <button className="ghost" onClick={closeModal}>Закрыть</button>
      </div>
    </>
  )
}
