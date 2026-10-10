import { NavLink, Navigate, Outlet } from 'react-router-dom'
import ModalHost from '../components/ModalHost.jsx'
import Tooltips from '../components/Tooltips.jsx'
import { useAuth } from '../context/auth.js'
import DataProvider from '../context/DataProvider.jsx'
import { useData } from '../context/data.js'
import { DEMO } from '../lib/demo.js'

const NAV = [
  { to: '/containers', label: 'Контейнеры', tip: 'Машины в Proxmox, внутри которых работают ловушки' },
  { to: '/overview', label: 'Обзор', tip: 'Сводка и лента атак в реальном времени' },
  { to: '/traps', label: 'Ловушки', tip: 'Каталог всех типов ловушек, которые умеет платформа' },
  { to: '/profiles', label: 'Профили', tip: 'Шаблоны ловушек: уровень, порты, баннеры, приманки' },
]

function Shell() {
  const { user, logout } = useAuth()
  const { orchError } = useData()
  return (
    <>
      <header className="topbar">
        <NavLink to="/containers" className="brand" aria-label="HoneyForge">
          <img src={import.meta.env.BASE_URL + 'favicon.png'} width="32" height="32" alt="" />
          <b>Honey<span>Forge</span></b>
        </NavLink>
        <nav aria-label="Разделы">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} data-tip={n.tip} className={({ isActive }) => (isActive ? 'on' : '')}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="who">
          <span><b>{user.username}</b> · <span>{user.role}</span></span>
          <button className="ghost" data-tip="Завершить сеанс" onClick={logout}>Выйти</button>
        </div>
      </header>

      <main>
        {DEMO && (
          <div className="demo" role="status">
            Демо-режим: данные вымышленные, бэкенд не используется, изменения не сохраняются.
          </div>
        )}
        {orchError && (
          <div className="demo" role="status">
            Proxmox недоступен: {orchError}. Машины не показываются, остальное работает.
          </div>
        )}
        <Outlet />
      </main>

      <footer className="credits">
        <span>HoneyForge · UmirHack III</span>
        <span>Команда:</span>
        <a href="https://github.com/DanielE330" target="_blank" rel="noopener noreferrer" data-tip="Автор и тимлид проекта">DanielE330</a>
        <span className="role">автор</span>
        <span>·</span>
        <a href="https://github.com/Lunarflux-hub" target="_blank" rel="noopener noreferrer" data-tip="Контрибьютер: бэкенд, Docker, интеграция с Proxmox">Lunarflux-hub</a>
        <span className="role">контрибьютер</span>
      </footer>
      <ModalHost />
      <Tooltips />
    </>
  )
}

// Панель доступна только с активной сессией; данные центра грузятся после входа
export default function AppLayout() {
  const { status } = useAuth()
  if (status === 'loading') return <div className="splash">Загрузка…</div>
  if (status === 'anon') return <Navigate to="/login" replace />
  return (
    <DataProvider>
      <Shell />
    </DataProvider>
  )
}
