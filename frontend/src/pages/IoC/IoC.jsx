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
  const [artifacts, setArtifacts] = useState(null)

  useEffect(() => {
    let alive = true
    fetch('/api/iocs.csv', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(t('Ошибка {status}', { status: r.status })))))
      .then((text) => alive && setRows(parseCsv(text)))
      .catch((e) => showToast(e.message, true))

    fetch('/api/artifacts', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(t('Ошибка {status}', { status: r.status })))))
      .then((d) => alive && setArtifacts(d.items || []))
      .catch(() => {})

    return () => { alive = false }
  }, [showToast, t])

  const copy = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text)
      showToast(t('Скопировано') + (label ? ` (${label})` : ''))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }

  return (
    <section>
      <div className="toolbar">
        <a className="btn" href="/api/iocs.csv" data-tip={t('Список IP атакующих для межсетевого экрана или таблицы')}>{t('Скачать IP (CSV)')}</a>
        <a className="btn" href="/api/iocs-hashes.csv" data-tip={t('Хэши SHA-256 загруженных атакующими файлов')}>{t('Скачать хэши файлов (CSV)')}</a>
        <a className="btn" href="/api/iocs.stix.json" data-tip={t('Индикаторы в формате STIX 2.1 (IP и хэши файлов) для SIEM и платформ обмена угрозами (MISP, OpenCTI)')}>{t('Скачать STIX 2.1')}</a>
        <span className="spacer" />
        <span className="hint">{t('Источников: {n}', { n: rows ? rows.length : 0 })}</span>
      </div>
      <div className="card">
        <h3>
          {t('Индикаторы компрометации (IP-адреса)')}
          <HelpMark text={t('IoC — IP-адреса, с которых были обращения к ловушкам. Легитимного трафика к ловушкам нет, поэтому любой такой адрес подозрителен.')} />
        </h3>
        <table className="rows">
          <thead><tr><th>IP</th><th>{t('Страна')}</th><th>ASN</th><th>{t('Провайдер')}</th><th>{t('Событий')}</th><th>{t('Впервые')}</th><th>{t('Последний раз')}</th></tr></thead>
          <tbody>
            {rows && rows.map((r) => (
              <tr key={r.ip} className="click" onClick={() => copy(r.ip, r.ip)} data-tip={t('Нажмите, чтобы скопировать IP')}>
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

      <div className="card" style={{ marginTop: '20px' }}>
        <h3>
          {t('Хэши файлов атакующих (SHA-256)')}
          <HelpMark text={t('Хэши вредоносных скриптов, дропперов и пейлоадов, загруженных через SFTP/SCP или записанных в консоли.')} />
        </h3>
        <table className="rows">
          <thead><tr><th>SHA-256</th><th>{t('Файл')}</th><th>{t('Размер')}</th><th>{t('Тип')}</th><th>{t('Источник')}</th><th>{t('Последний раз')}</th></tr></thead>
          <tbody>
            {artifacts && artifacts.map((a) => (
              <tr key={a.sha256} className="click" onClick={() => copy(a.sha256, a.name || 'SHA-256')} data-tip={t('Нажмите, чтобы скопировать хэш')}>
                <td className="m">{a.sha256.slice(0, 20)}…</td>
                <td className="m">{a.name || '—'}</td>
                <td className="m">{a.size} B</td>
                <td>{a.kind}</td>
                <td className="m">{a.src_ip || '—'}</td>
                <td className="m">{fmtDateTime(Date.parse(a.last_seen))}</td>
              </tr>
            ))}
            {artifacts && !artifacts.length && <tr><td colSpan={6} className="empty">{t('Вредоносных файлов пока не зафиксировано')}</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
