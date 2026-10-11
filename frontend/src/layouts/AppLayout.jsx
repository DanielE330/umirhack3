import { Bell, ChartColumn, FileDown, FileWarning, Layers, LayoutDashboard, Radar, ScrollText, Server, Settings, Users } from 'lucide-react'
import { NavLink, Navigate, Outlet, useLocation } from 'react-router-dom'
import ModalHost from '../components/ModalHost.jsx'
import Tooltips from '../components/Tooltips.jsx'
import { useAuth } from '../context/auth.js'
import DataProvider from '../context/DataProvider.jsx'
import { useData } from '../context/data.js'
import { useLanguage } from '../context/language.js'
import { useLayout } from '../context/layout.js'
import { DEMO } from '../lib/demo.js'

const NAV = [
  { to: '/containers', label: 'Контейнеры', tip: 'Машины в Proxmox, внутри которых работают ловушки', icon: Server },
  { to: '/overview', label: 'Обзор', tip: 'Сводка и лента атак в реальном времени', icon: LayoutDashboard },
  { to: '/events', label: 'События', tip: 'Вся история событий с фильтрами по времени, источнику, типу и опасности', icon: ScrollText },
  { to: '/alerts', label: 'Тревоги', tip: 'Перебор паролей и срабатывания файлов-приманок', icon: Bell },
  { to: '/analytics', label: 'Аналитика', tip: 'Графики за 24 часа: динамика, источники, страны, пароли', icon: ChartColumn },
  { to: '/ioc', label: 'IoC', tip: 'Индикаторы компрометации: список IP и экспорт в CSV и STIX', icon: FileDown },
  { to: '/traps', label: 'Ловушки', tip: 'Каталог всех типов ловушек, которые умеет платформа', icon: Radar },
  { to: '/profiles', label: 'Профили', tip: 'Шаблоны ловушек: уровень, порты, баннеры, приманки', icon: Layers },
  { to: '/files', label: 'Файлы', tip: 'Файлы, которые атакующие загрузили на ловушки: хэши и содержимое', icon: FileWarning },
  { to: '/users', label: 'Пользователи', tip: 'Операторы панели: создание, роли, блокировка, сброс 2FA', icon: Users, admin: true },
  { to: '/audit', label: 'Аудит', tip: 'Журнал действий операторов: кто и что менял в панели', icon: ScrollText, admin: true },
  { to: '/settings', label: 'Настройки', tip: 'Язык, расположение навигации и учётная запись', icon: Settings },
]

function Shell() {
  const { user, logout } = useAuth()
  const { orchError } = useData()
  const { t } = useLanguage()
  const { layout } = useLayout()
  const { pathname } = useLocation() // новый key при смене раздела перезапускает анимацию появления
  return (
    <div className={'app-shell ' + (layout === 'side' ? 'layout-side' : 'layout-top')}>
      <header className="topbar">
        <NavLink to="/containers" className="brand" aria-label="HoneyForge">
          <img src={import.meta.env.BASE_URL + 'favicon.png'} width="32" height="32" alt="" />
          <b>Honey<span>Forge</span></b>
        </NavLink>
        <nav aria-label={t('Разделы')}>
          {NAV.filter((n) => !n.admin || user.role === 'admin').map((n) => {
            const Icon = n.icon
            return (
              <NavLink key={n.to} to={n.to} data-tip={t(n.tip)} className={({ isActive }) => (isActive ? 'on' : '')}>
                <Icon size={16} strokeWidth={1.5} aria-hidden="true" />
                <span>{t(n.label)}</span>
              </NavLink>
            )
          })}
        </nav>
        <div className="who">
          <span><b>{user.username}</b> · <span>{user.role}</span></span>
          <button className="ghost" data-tip={t('Завершить сеанс')} onClick={logout}>{t('Выйти')}</button>
        </div>
      </header>

      <main>
        {DEMO && (
          <div className="demo" role="status">
            {t('Демо-режим: данные вымышленные, бэкенд не используется, изменения не сохраняются.')}
          </div>
        )}
        {orchError && (
          <div className="demo" role="status">
            {t('Proxmox недоступен: {err}. Машины не показываются, остальное работает.', { err: orchError })}
          </div>
        )}
        <div key={pathname} className="page"><Outlet /></div>
      </main>

      <ModalHost />
      <Tooltips />
    </div>
  )
}

// Панель доступна только с активной сессией; данные центра грузятся после входа
export default function AppLayout() {
  const { status } = useAuth()
  const { t } = useLanguage()
  if (status === 'loading') return <div className="splash">{t('Загрузка…')}</div>
  if (status === 'anon') return <Navigate to="/login" replace />
  return (
    <DataProvider>
      <Shell />
    </DataProvider>
  )
}
