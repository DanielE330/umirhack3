import { geoNaturalEarth1, geoPath } from 'd3-geo'
import { useEffect, useMemo, useState } from 'react'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'
import { HelpMark } from '../../components/common.jsx'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { fmtDateTime } from '../../lib/model.js'

const W = 960
const H = 500
const PERIODS = [['24h', '24 часа'], ['7d', '7 дней'], ['30d', '30 дней'], ['all', 'Всё время']]

// проекция и контуры стран считаем один раз: карта целиком в бандле, внешних запросов (тайлов) нет
const projection = geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' })
const path = geoPath(projection)
const LAND = feature(world, world.objects.countries).features.map((f, i) => ({ id: i, d: path(f) })).filter((x) => x.d)
const SPHERE = path({ type: 'Sphere' })

const label = (g) => (g && g.country_code && g.country_code !== '--'
  ? [g.city, g.country].filter(Boolean).join(', ')
  : '')

// Карта источников атак и список «кто и откуда нападает»: пузырь на карте — IP, размер — число событий.
export default function AttackMap() {
  const { t, locale } = useLanguage()
  const { showToast } = useUi()
  const [period, setPeriod] = useState('24h')
  const [data, setData] = useState(null)

  useEffect(() => {
    let alive = true
    const load = () => api('/api/sources?period=' + period).then((d) => alive && setData(d)).catch((e) => showToast(e.message, true))
    load()
    const timer = setInterval(load, 15000)
    return () => { alive = false; clearInterval(timer) }
  }, [period, showToast])

  const points = useMemo(() => {
    if (!data) return []
    const max = Math.max(1, ...data.items.map((i) => i.events))
    return data.items
      .filter((i) => i.geo && i.geo.lat != null && i.geo.lon != null)
      .map((i) => {
        const [x, y] = projection([i.geo.lon, i.geo.lat]) || [-99, -99]
        return { ...i, x, y, r: 4 + 16 * Math.sqrt(i.events / max) }
      })
  }, [data])

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
        <div className="chips" role="radiogroup" aria-label={t('Период')}>
          {PERIODS.map(([v, name]) => (
            <button key={v} type="button" role="radio" aria-checked={v === period} className={v === period ? 'on' : ''} onClick={() => setPeriod(v)}>{t(name)}</button>
          ))}
        </div>
        <span className="spacer" />
        <span className="hint">{data ? t('Источников: {n} · на карте: {m}', { n: data.items.length, m: points.length }) : t('Загрузка…')}</span>
      </div>

      <div className="card">
        <h3>
          {t('Откуда нападают')}
          <HelpMark text={t('Пузырь — IP-адрес атакующего, размер — число его событий. Положение определяется по публичной базе IP и приблизительно. Частные адреса (своя сеть) на карте не показываются.')} />
        </h3>
        <svg className="attack-map" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={t('Карта источников атак')}>
          <path className="sea" d={SPHERE} />
          {LAND.map((c) => <path key={c.id} className="land" d={c.d} />)}
          {points.map((p) => (
            <circle key={p.ip} className="dot" cx={p.x} cy={p.y} r={p.r}
              data-tip={`${p.ip} · ${label(p.geo)} · ${p.geo.asn || ''} ${p.geo.org || ''} · ${t('событий')}: ${p.events.toLocaleString(locale)}`} />
          ))}
        </svg>
        {data && !points.length && <p className="hint">{t('Пока нет источников с известным положением: когда атаки придут с публичных адресов, они появятся здесь.')}</p>}
      </div>

      <div className="cols">
        <div className="card">
          <h3>{t('Страны')}</h3>
          <table className="rows">
            <thead><tr><th>{t('Страна')}</th><th>{t('Адресов')}</th><th>{t('Событий')}</th></tr></thead>
            <tbody>
              {data && data.countries.map((c) => (
                <tr key={c.country_code}>
                  <td><span className="cc">{c.country_code}</span>{c.country}</td>
                  <td>{c.ips}</td>
                  <td>{c.events.toLocaleString(locale)}</td>
                </tr>
              ))}
              {data && !data.countries.length && <tr><td className="empty" colSpan={3}>{t('Нет данных')}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>{t('Кто нападает')}</h3>
          <table className="rows">
            <thead>
              <tr>
                <th>IP</th><th>{t('Откуда')}</th><th>ASN</th><th>{t('Событий')}</th><th data-tip={t('Попытки входа / команды / срабатывания приманок')}>{t('Вход / команд / приманок')}</th>
                <th>{t('Ловушек')}</th><th data-tip={t('Максимальная оценка опасности HoneyMind (0–100)')}>{t('Риск')}</th><th>{t('Последний раз')}</th>
              </tr>
            </thead>
            <tbody>
              {data && data.items.map((i) => (
                <tr key={i.ip} className="click" onClick={() => copy(i.ip)} data-tip={t('Нажмите, чтобы скопировать IP')}>
                  <td className="m">{i.ip}</td>
                  <td>{label(i.geo) || (i.geo && i.geo.country === 'Локальная сеть' ? t('Локальная сеть') : '—')}</td>
                  <td className="m" data-tip={(i.geo && i.geo.org) || undefined}>{(i.geo && i.geo.asn) || ''}</td>
                  <td>{i.events.toLocaleString(locale)}</td>
                  <td className="m">{i.auth_attempts} / {i.commands} / {i.honeytokens}</td>
                  <td>{i.traps}</td>
                  <td>{i.max_score != null ? <span className={'risk-score' + (i.max_score >= 60 ? ' hot' : '')}>{i.max_score}</span> : ''}</td>
                  <td className="m">{fmtDateTime(Date.parse(i.last_seen))}</td>
                </tr>
              ))}
              {data && !data.items.length && <tr><td className="empty" colSpan={8}>{t('За этот период атак нет')}</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
