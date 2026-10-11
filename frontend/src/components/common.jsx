import { useEffect, useRef, useState } from 'react'
import { useLanguage } from '../context/language.js'
import { EVENT_HELP, HELP, STATES } from '../lib/model.js'

// Знак «?» с подсказкой
export function HelpMark({ text }) {
  return <span className="q" tabIndex={0} data-tip={text} aria-label={text}>?</span>
}

export function LevelTag({ level }) {
  const { t } = useLanguage()
  const label = level === 'low' ? 'Low' : level === 'medium' ? 'Medium' : level === 'high' ? 'High' : '—'
  return <span className={'tag ' + level} data-tip={HELP[level] ? t(HELP[level]) : t('Профиль не задан')}>{label}</span>
}

export function TypeTag({ type }) {
  const { t } = useLanguage()
  return <span className={'tag t-' + type} data-tip={EVENT_HELP[type] ? t(EVENT_HELP[type]) : type}>{type}</span>
}

export function StateBadge({ state }) {
  const { t } = useLanguage()
  return (
    <span className="cstate" data-tip={t(STATES[state].hint)}>
      <span className={'dot ' + state} />
      <span className={'st-label ' + state}>{t(STATES[state].label)}</span>
    </span>
  )
}

// Переключатель «Включён/Выключен»: ползунок двигается сразу, действие — после анимации
export function Switch({ on, tip, onToggle, disabled }) {
  const { t } = useLanguage()
  const [opt, setOpt] = useState(null) // оптимистичное значение, пока не пришёл ответ
  const timer = useRef(0)
  useEffect(() => () => clearTimeout(timer.current), [])
  const checked = opt && opt.from === on ? opt.value : on
  const busy = disabled || checked !== on
  const click = (e) => {
    e.stopPropagation()
    setOpt({ from: on, value: !on })
    timer.current = setTimeout(onToggle, 280)
  }
  return (
    <button type="button" role="switch" aria-checked={checked} data-tip={tip} disabled={disabled}
      className={'switch' + (busy ? ' busy' : '')} onClick={click}>
      <span className="track"><span className="knob" /></span>
      <span>{checked ? t('Включён') : t('Выключен')}</span>
    </button>
  )
}

// Опасное действие подтверждается вторым нажатием в течение 3 секунд
export function ArmedButton({ label, armLabel, onConfirm, className = 'ghost', tip, ...rest }) {
  const [armed, setArmed] = useState(false)
  const timer = useRef(0)
  useEffect(() => () => clearTimeout(timer.current), [])
  const click = (e) => {
    e.stopPropagation()
    if (armed) {
      clearTimeout(timer.current)
      setArmed(false)
      onConfirm()
      return
    }
    setArmed(true)
    timer.current = setTimeout(() => setArmed(false), 3000)
  }
  return (
    <button type="button" data-tip={tip} className={className + (armed ? ' arm' : '')} onClick={click} {...rest}>
      {armed ? armLabel : label}
    </button>
  )
}

// Строки «ключ — значение» в карточках и окнах
export function Kv({ rows }) {
  const { t } = useLanguage()
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div className="kv-row" key={k}>
          <dt>{t(k)}</dt>
          <dd>{v === '' || v == null ? '—' : v}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Field({ label, children }) {
  const { t } = useLanguage()
  return (
    <div>
      <label>{t(label)}</label>
      {children}
    </div>
  )
}
