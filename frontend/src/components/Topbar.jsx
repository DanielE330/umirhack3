import { useEffect, useRef, useState } from 'react'
import { Bell, ChevronDown, Menu, PanelLeftClose, PanelLeftOpen, Search, User } from 'lucide-react'
import Button from './Button.jsx'
import StatusBadge from './StatusBadge.jsx'

function UserMenu() {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    const onPointerDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    const onKeyDown = (e) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  return (
    <div className="user-menu" ref={ref}>
      <button
        type="button"
        className="user-menu__trigger"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="user-menu__avatar">
          <User size={14} aria-hidden="true" />
        </span>
        <span className="user-menu__label">Оператор</span>
        <ChevronDown size={14} aria-hidden="true" />
      </button>
      {open && (
        <div className="user-menu__dropdown">
          <div className="user-menu__name">Оператор</div>
          <p className="user-menu__note">Авторизация ещё не подключена к backend.</p>
          <Button size="sm" disabled title="Подготовлено к реализации">
            Выйти
          </Button>
        </div>
      )}
    </div>
  )
}

export default function Topbar({ collapsed, onToggleCollapse, onOpenMobile }) {
  const CollapseIcon = collapsed ? PanelLeftOpen : PanelLeftClose

  return (
    <header className="topbar">
      <Button
        className="topbar__menu-btn"
        variant="ghost"
        icon={Menu}
        aria-label="Открыть меню"
        aria-controls="sidebar"
        onClick={onOpenMobile}
      />
      <Button
        className="topbar__collapse-btn"
        variant="ghost"
        icon={CollapseIcon}
        aria-label={collapsed ? 'Развернуть меню' : 'Свернуть меню'}
        aria-controls="sidebar"
        aria-expanded={!collapsed}
        onClick={onToggleCollapse}
      />

      <div className="topbar__search">
        <Search className="topbar__search-icon" size={16} aria-hidden="true" />
        <input
          type="search"
          className="topbar__search-input"
          placeholder="Поиск по ловушкам и событиям"
          aria-label="Глобальный поиск"
          disabled
          title="Подготовлено к реализации"
        />
      </div>

      <div className="topbar__right">
        <div className="topbar__conn" title="Состояние связи с центром">
          <StatusBadge status="offline" label="Центр: нет данных" />
        </div>
        <Button
          variant="ghost"
          icon={Bell}
          aria-label="Уведомления"
          disabled
          title="Подготовлено к реализации"
        />
        <UserMenu />
      </div>
    </header>
  )
}
