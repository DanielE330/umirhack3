import { Hexagon, X } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { NAV_GROUPS } from '../app/navigation.js'
import Button from './Button.jsx'

export default function Sidebar({ collapsed, mobileOpen, onClose }) {
  return (
    <aside
      id="sidebar"
      className={`sidebar${mobileOpen ? ' sidebar--open' : ''}`}
      aria-label="Основная навигация"
    >
      <div className="sidebar__brand">
        <span className="sidebar__logo">
          <Hexagon size={20} aria-hidden="true" />
        </span>
        <span className="sidebar__name">HoneyForge</span>
        <Button
          className="sidebar__close"
          variant="ghost"
          icon={X}
          aria-label="Закрыть меню"
          onClick={onClose}
        />
      </div>

      <nav className="sidebar__nav">
        {NAV_GROUPS.map((group) => (
          <div className="sidebar__group" key={group.title}>
            <div className="sidebar__group-title">{group.title}</div>
            <ul className="sidebar__list">
              {group.items.map(({ to, label, icon: Icon }) => (
                <li key={to}>
                  <NavLink
                    to={to}
                    className="nav-link"
                    title={collapsed ? label : undefined}
                    aria-label={label}
                    onClick={onClose}
                  >
                    <Icon size={18} aria-hidden="true" />
                    <span className="nav-link__label">{label}</span>
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  )
}
