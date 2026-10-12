import { createHashRouter, Navigate } from 'react-router-dom'
import AppLayout from '../layouts/AppLayout.jsx'
import Alerts from '../pages/Alerts/Alerts.jsx'
import Analytics from '../pages/Analytics/Analytics.jsx'
import Audit from '../pages/Audit/Audit.jsx'
import Containers from '../pages/Containers/Containers.jsx'
import Events from '../pages/Events/Events.jsx'
import Files from '../pages/Files/Files.jsx'
import IoC from '../pages/IoC/IoC.jsx'
import AttackMap from '../pages/Map/Map.jsx'
import Login from '../pages/Login/Login.jsx'
import Overview from '../pages/Overview/Overview.jsx'
import Profiles from '../pages/Profiles/Profiles.jsx'
import Settings from '../pages/Settings/Settings.jsx'
import Traps from '../pages/Traps/Traps.jsx'
import Users from '../pages/Users/Users.jsx'
import Wiki from '../pages/Wiki/Wiki.jsx'

// Hash-маршруты: центр отдаёт только index.html, поэтому /#/overview открывается и после обновления страницы
export const router = createHashRouter([
  { path: '/login', element: <Login /> },
  // документация открывается без входа: её можно будет вынести на отдельный хост
  { path: '/wiki', element: <Wiki /> },
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Navigate to="/containers" replace /> },
      { path: 'containers', element: <Containers /> },
      { path: 'overview', element: <Overview /> },
      { path: 'events', element: <Events /> },
      { path: 'alerts', element: <Alerts /> },
      { path: 'analytics', element: <Analytics /> },
      { path: 'map', element: <AttackMap /> },
      { path: 'ioc', element: <IoC /> },
      { path: 'traps', element: <Traps /> },
      { path: 'profiles', element: <Profiles /> },
      { path: 'files', element: <Files /> },
      { path: 'users', element: <Users /> },
      { path: 'audit', element: <Audit /> },
      { path: 'settings', element: <Settings /> },
      { path: '*', element: <Navigate to="/containers" replace /> },
    ],
  },
])
