import { useEffect, useState } from 'react'
import { HelpMark } from '../../components/common.jsx'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { fmtDateTime } from '../../lib/model.js'

// Разбор CSV из /api/iocs.csv (значения в кавычках с запятыми не встречаются: поля — IP, коды, числа и даты, org уже безопасен)
function parseCsv(text) {
  const rows = text.trim().split(/\r?\n/).map((line) => line.split(','))
  const head = rows.shift() || []
  return rows.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] || ''])))
}

export default function IoC() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const [rows, setRows] = useState(null)

  useEffect(() => {
    let alive = true
    fetch('/api/iocs.csv', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(t('Ошибка {status}', { status: r.status })))))
      .then((text) => alive && setRows(parseCsv(text)))
      .catch((e) => showToast(e.message, true))
    return () => { alive = false }
  }, [showToast, t])

  const copy = async (ip) => {
    try {
      await navigator.clipboard.writeText(ip)
      showToast(t('Скопировано'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }

  return (
    <section>
      <div className="toolbar">
        <a className="btn" href="/api/iocs.csv" data-tip={t('Список IP атакующих для межсетевого экрана или таблицы')}>{t('Скачать CSV')}</a>
        <a className="btn" href="/api/iocs.stix.json" data-tip={t('Индикаторы в формате STIX 2.1 для SIEM и платформ обмена угрозами (MISP, OpenCTI)')}>{t('Скачать STIX 2.1')}</a>
        <span className="spacer" />
        <span className="hint">{t('Источников: {n}', { n: rows ? rows.length : 0 })}</span>
      </div>
      <div className="card">
        <h3>
          {t('Индикаторы компрометации')}
          <HelpMark text={t('IoC — IP-адреса, с которых были обращения к ловушкам. Легитимного трафика к ловушкам нет, поэтому любой такой адрес подозрителен.')} />
        </h3>
        <table className="rows">
          <thead><tr><th>IP</th><th>{t('Страна')}</th><th>ASN</th><th>{t('Провайдер')}</th><th>{t('Событий')}</th><th>{t('Впервые')}</th><th>{t('Последний раз')}</th></tr></thead>
          <tbody>
            {rows && rows.map((r) => (
              <tr key={r.ip} className="click" onClick={() => copy(r.ip)} data-tip={t('Нажмите, чтобы скопировать IP')}>
                <td className="m">{r.ip}</td>
                <td>{r.country && r.country !== '--' ? <span className="cc">{r.country}</span> : ''}</td>
                <td className="m">{r.asn}</td>
                <td>{r.org}</td>
                <td>{r.events}</td>
                <td className="m">{fmtDateTime(Date.parse(r.first_seen))}</td>
                <td className="m">{fmtDateTime(Date.parse(r.last_seen))}</td>
              </tr>
            ))}
            {rows && !rows.length && <tr><td colSpan={7} className="empty">{t('Индикаторов пока нет')}</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
