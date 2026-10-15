import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../lib/api.js'
import { useAuth } from '../../context/auth.js'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { fmtDateTime } from '../../lib/model.js'
import { Kv } from '../common.jsx'
import TerminalPlayer from '../TerminalPlayer.jsx'

export default function EventModal({ ev }) {
  const { trapByName, setEventFilter } = useData()
  const { closeModal, showToast } = useUi()
  const { openTrap } = useModals()
  const { t } = useLanguage()
  const navigate = useNavigate()
  const { can } = useAuth()
  const [sess, setSess] = useState(null)
  useEffect(() => {
    if (!ev.session_id) return undefined
    let alive = true
    api('/api/sessions/' + ev.session_id).then((d) => alive && setSess(d)).catch(() => {})
    return () => { alive = false }
  }, [ev.session_id])
  const human = sess && sess.is_human !== null && sess.is_human !== undefined
    ? (sess.is_human ? t('человек') : t('бот / скрипт')) + (sess.human_probability != null ? ' (' + Math.round(sess.human_probability * 100) + '%)' : '')
    : ''

  const intentText = sess && sess.intent_prediction && sess.intent_prediction.predicted_technique
    ? `${sess.intent_prediction.predicted_technique} (${Math.round((sess.intent_prediction.probability || 0) * 100)}%) — ${sess.intent_prediction.predicted_name || ''}`
    : ''

  const engageText = sess && sess.mitre_engage && Array.isArray(sess.mitre_engage.activities) && sess.mitre_engage.activities.length
    ? sess.mitre_engage.activities.map((a) => a.id + ' (' + (a.name || '') + ')').join(', ')
    : ''

  const hasshText = sess && sess.hassh_profile
    ? `${sess.hassh_profile.client_guess || 'Клиент'} [${(sess.hassh_profile.hassh || '').slice(0, 8)}...]`
    : ''

  const filterBy = (patch) => {
    closeModal()
    setEventFilter({ q: '', type: '', trap: '', ...patch })
    navigate('/overview')
  }
  const copyIp = async () => {
    try {
      await navigator.clipboard.writeText(ev.src_ip)
      showToast(t('Скопировано'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }
  const openTrapOf = () => {
    const tr = trapByName(ev.trap)
    if (tr) openTrap(tr)
    else showToast(t('Ловушка уже удалена'), true)
  }

  return (
    <>
      <Kv rows={[
        ['Время', fmtDateTime(ev.ts)], ['Машина', ev.container], ['Ловушка', ev.trap], ['Тип', ev.type],
        ['Источник', ev.src_ip + ':' + ev.src_port],
        ['Страна / город', ev.geo ? [ev.geo.country, ev.geo.city].filter(Boolean).join(', ') : ''],
        ['ASN / провайдер', ev.geo ? [ev.geo.asn, ev.geo.org].filter(Boolean).join(' · ') : ''], ['Порт ловушки', ev.dst_port], ['Протокол', ev.proto],
        ['Сессия', ev.session_id], ['Логин', ev.username], ['Пароль', ev.password], ['Команда / запрос', ev.command],
        ['Файл (SHA-256)', (ev.data && ev.data.sha256) || ''],
        ['Оценка опасности', ev.threat_score != null ? ev.threat_score + ' / 100' + (ev.threat_score >= 60 ? ' — ' + t('опасно') : '') : ''],
        ['Категория (HoneyMind)', ev.category || ''],
        ['Сессия: длительность', sess ? sess.summary.duration_seconds + ' ' + t('с') + ' · ' + t('команд') + ': ' + sess.summary.commands + ' · ' + t('попыток входа') + ': ' + sess.summary.auth_attempts : ''],
        ['Человек или бот', human],
        ['Почему (HoneyMind)', (sess && sess.human_reason) || ''],
        ['Следующий шаг (Markov)', intentText],
        ['MITRE Engage (Deception)', engageText],
        ['HASSH клиент', hasshText],
      ]} />
      <div className="inline">
        <button className="ghost" onClick={() => filterBy({ q: ev.src_ip })}>{t('⌕ Все события этого IP')}</button>
        <button className="ghost" onClick={() => filterBy({ trap: ev.trap })}>{t('☰ События этой ловушки')}</button>
        <button className="ghost" onClick={copyIp}>{t('⧉ Копировать IP')}</button>
        <button className="ghost" onClick={openTrapOf}>{t('→ Открыть ловушку')}</button>
        {ev.data && ev.data.artifact && can('files.download') && <a className="ghost btn" href={'/api/artifacts/' + ev.data.artifact + '/download'}>{t('⬇ Скачать файл')}</a>}
      </div>
      {ev.session_id && (
        <div className="inline" style={{ marginTop: '0.5rem', flexWrap: 'wrap', gap: '0.4rem' }}>
          {can('events.export') && (
            <a className="ghost btn" href={'/api/sessions/' + ev.session_id + '/sigma.yml'} download title={t('Скачать сгенерированное правило Sigma')}>
              {t('📥 Sigma (YAML)')}
            </a>
          )}
          {can('events.export') && (
            <a className="ghost btn" href={'/api/sessions/' + ev.session_id + '/yara.yar'} download title={t('Скачать сигнатуру YARA')}>
              {t('🔍 YARA (.yar)')}
            </a>
          )}
          {can('events.view') && (
            <a className="ghost btn" href={'/api/sessions/' + ev.session_id + '/report.md'} target="_blank" rel="noreferrer" download title={t('Скачать Executive Brief для руководства')}>
              {t('📋 Отчёт C-Level')}
            </a>
          )}
          {can('events.view') && (
            <a className="ghost btn" href={'/api/sessions/' + ev.session_id + '/dfir.md'} target="_blank" rel="noreferrer" download title={t('Скачать полный технический DFIR-отчёт')}>
              {t('🔬 DFIR Отчёт')}
            </a>
          )}
          {can('events.export') && (
            <a className="ghost btn" href={'/api/sessions/' + ev.session_id + '/stix.json'} download title={t('Скачать граф STIX 2.1 Bundle (OpenCTI / MISP)')}>
              {t('🌐 STIX 2.1 (JSON)')}
            </a>
          )}
        </div>
      )}
      {sess && sess.summary && Array.isArray(sess.summary.commands_list) && sess.summary.commands_list.length > 0 && (
        <TerminalPlayer commands={sess.summary.commands_list} sessionId={ev.session_id} />
      )}
    </>
  )
}
