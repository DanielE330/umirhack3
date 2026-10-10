import { useEffect, useId, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'

// Самописный выпадающий список: чистый UI, без привязки к данным.
// options: [{ value, label }]. onChange получает { target: { value } }, как у нативного select,
// поэтому обработчики родителей не меняются.
export default function Select({ options, value, onChange, id, className = '', 'aria-label': ariaLabel, 'data-tip': tip }) {
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(-1)
  const root = useRef(null)
  const listId = useId()
  const current = options.find((o) => o.value === value)

  // закрытие по клику вне компонента
  useEffect(() => {
    if (!open) return undefined
    const onDown = (e) => {
      if (!root.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const show = () => {
    setActive(Math.max(0, options.findIndex((o) => o.value === value)))
    setOpen(true)
  }
  const pick = (v) => {
    onChange({ target: { value: v } })
    setOpen(false)
  }
  const onKey = (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      if (!open) return show()
      const d = e.key === 'ArrowDown' ? 1 : -1
      setActive((i) => (i + d + options.length) % options.length)
    } else if (e.key === 'Enter' || e.key === ' ') {
      if (!open) return
      e.preventDefault()
      pick(options[active].value)
    } else if (e.key === 'Escape' && open) {
      e.stopPropagation() // не закрываем и модальное окно вместе со списком
      setOpen(false)
    }
  }

  return (
    <div ref={root} className={'sel' + (open ? ' open' : '') + (className ? ' ' + className : '')} data-tip={tip}>
      <button
        type="button"
        id={id}
        className="sel-trigger"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => (open ? setOpen(false) : show())}
        onKeyDown={onKey}
      >
        <span className="sel-value">{current ? current.label : ''}</span>
        <ChevronDown className="sel-chevron" size={16} strokeWidth={1.5} aria-hidden="true" />
      </button>
      <ul id={listId} role="listbox" className="sel-menu" aria-hidden={!open}>
        {options.map((o, i) => (
          <li
            key={o.value}
            role="option"
            aria-selected={o.value === value}
            className={'sel-option' + (i === active ? ' active' : '') + (o.value === value ? ' selected' : '')}
            onMouseEnter={() => setActive(i)}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => pick(o.value)}
          >
            {o.label}
          </li>
        ))}
      </ul>
    </div>
  )
}
