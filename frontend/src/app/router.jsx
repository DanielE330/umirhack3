import { createHashRouter } from 'react-router-dom'
import { Allow, Home } from './Allow.jsx'
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
import Roles from '../pages/Roles/Roles.jsx'
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
      { index: true, element: <Home /> },
      { path: 'containers', element: <Allow path="/containers"><Containers /></Allow> },
      { path: 'overview', element: <Allow path="/overview"><Overview /></Allow> },
      { path: 'events', element: <Allow path="/events"><Events /></Allow> },
      { path: 'alerts', element: <Allow path="/alerts"><Alerts /></Allow> },
      { path: 'analytics', element: <Allow path="/analytics"><Analytics /></Allow> },
      { path: 'map', element: <Allow path="/map"><AttackMap /></Allow> },
      { path: 'ioc', element: <Allow path="/ioc"><IoC /></Allow> },
      { path: 'traps', element: <Allow path="/traps"><Traps /></Allow> },
      { path: 'profiles', element: <Allow path="/profiles"><Profiles /></Allow> },
      { path: 'files', element: <Allow path="/files"><Files /></Allow> },
      { path: 'roles', element: <Allow path="/roles"><Roles /></Allow> },
      { path: 'users', element: <Allow path="/users"><Users /></Allow> },
      { path: 'audit', element: <Allow path="/audit"><Audit /></Allow> },
      { path: 'settings', element: <Settings /> },
      { path: '*', element: <Home /> },
    ],
  },
])
