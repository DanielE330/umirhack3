import { useEffect, useState } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { HelpMark } from '../../components/common.jsx'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'

const COLORS = { n: '#f59e0b', auth: '#38bdf8', alert: '#ef4444', bar: '#f59e0b' }

function Top({ title, tip, rows }) {
  const { t } = useLanguage()
  return (
    <div className="card">
      <h3>{title}<HelpMark text={tip} /></h3>
      {rows && rows.length ? (
        <div className="chart-box short">
          <ResponsiveContainer>
            <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="currentColor" opacity={0.12} />
              <XAxis type="number" allowDecimals={false} stroke="currentColor" fontSize={11} />
              <YAxis type="category" dataKey="value" width={110} stroke="currentColor" fontSize={11} />
              <Tooltip />
              <Bar dataKey="count" name={t('Событий')} fill={COLORS.bar} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : <div className="empty">{t('Нет данных')}</div>}
    </div>
  )
}

// Аналитика за 24 часа: динамика по часам, типы событий, источники, логины и пароли.
export default function Analytics() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const [s, setS] = useState(null)

  useEffect(() => {
    let alive = true
    const load = () => api('/api/stats').then((d) => alive && setS(d)).catch((e) => showToast(e.message, true))
    load()
    const timer = setInterval(load, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [showToast])

  if (!s) return <section><p className="hint">{t('Загрузка…')}</p></section>
  const types = Object.entries(s.by_type).map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count)
  return (
    <section>
      <div className="card">
        <h3>
          {t('События по часам (24 часа)')}
          <HelpMark text={t('Всего событий, попыток входа и тревог в каждый час. Всплеск попыток входа без тревоги — медленный перебор.')} />
        </h3>
        <div className="chart-box">
          <ResponsiveContainer>
            <AreaChart data={s.by_hour} margin={{ left: 0, right: 12 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="currentColor" opacity={0.12} />
              <XAxis dataKey="t" stroke="currentColor" fontSize={11} interval={3} />
              <YAxis allowDecimals={false} stroke="currentColor" fontSize={11} />
              <Tooltip />
              <Legend />
              <Area type="monotone" dataKey="n" name={t('Все события')} stroke={COLORS.n} fill={COLORS.n} fillOpacity={0.25} />
              <Area type="monotone" dataKey="auth" name={t('Попытки входа')} stroke={COLORS.auth} fill={COLORS.auth} fillOpacity={0.2} />
              <Area type="monotone" dataKey="alert" name={t('Тревоги')} stroke={COLORS.alert} fill={COLORS.alert} fillOpacity={0.3} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="cols">
        <Top title={t('Типы событий')} tip={t('Из чего состоит активность: подключения, попытки входа, команды, запросы.')} rows={types} />
        <Top title={t('Источники (IP)')} tip={t('Адреса, с которых пришло больше всего событий за 24 часа.')} rows={s.top_sources} />
      </div>
      <div className="cols">
        <Top title={t('Страны')} tip={t('Страна источника по публичной базе IP; частные адреса не учитываются.')} rows={s.top_countries} />
        <Top title={t('Провайдеры (ASN)')} tip={t('Автономные системы источников: помогает увидеть хостинги и сети, откуда идёт сканирование.')} rows={s.top_asn} />
      </div>
      <div className="cols">
        <Top title={t('Логины')} tip={t('Какие имена пользователей пробуют чаще всего.')} rows={s.top_usernames} />
        <Top title={t('Пароли')} tip={t('Пароли из словарей перебора: показывает, какие списки используют атакующие.')} rows={s.top_passwords} />
      </div>
    </section>
  )
}
