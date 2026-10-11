import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { PVE, TYPE_INFO, pveCommands, resParts } from '../../lib/model.js'
import { Kv } from '../common.jsx'

export default function PveInfoModal({ vmid }) {
  const { containers, trapsOf } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const c = containers.find((x) => x.vmid === vmid)
  if (!c) return <p className="hint">{t('Машина уже удалена')}</p>
  const info = TYPE_INFO[c.type]
  const commands = pveCommands(c)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(commands)
      showToast(t('Скопировано'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }

  return (
    <>
      <Kv rows={[
        ['Тип', info.label + ' — ' + t(info.title)], ['VMID', c.vmid], ['Нода', c.node], ['Ресурсы', resParts(c).join(' · ')],
        ['Сеть', t(PVE.bridgeLabel)], ['IP', c.host], ['Ловушки', trapsOf(c.name).map((x) => x.name).join(', ') || '—'],
      ]} />
      <h4>{t('Что делает центр')}</h4>
      <ol className="steps">
        <li><b>{t('Клонирование:')}</b> {t('оркестратор через Proxmox API делает полный клон шаблона {tpl} в {kind} {vmid} на хранилище {storage}.', {
          tpl: PVE.templates[c.type] || '—', kind: info.kind, vmid: c.vmid, storage: PVE.storage,
        })}</li>
        <li><b>{t('Ресурсы и сеть:')}</b> {t('{res}; интерфейс в {bridge} (DMZ) с адресом {ip}, без доступа в домашнюю сеть. Тег honeyforge: чужие машины оркестратор не трогает.', {
          res: resParts(c).join(', '), bridge: c.bridge, ip: c.host || t('из 10.20.0.0/24'),
        })}</li>
        <li><b>{t('Запуск:')}</b> {t('машина стартует; агент в ней подключается к центру и поднимает ловушки (кнопка «Подключить агента» в окне ловушки).')}</li>
      </ol>
      <h4>{t('Эквивалентные команды Proxmox (для справки и ручной отладки)')}</h4>
      <pre>{commands}</pre>
      <div className="actions">
        <button className="ghost" onClick={copy}>{t('Копировать команды')}</button>
        <button className="ghost" onClick={closeModal}>{t('Закрыть')}</button>
      </div>
    </>
  )
}
