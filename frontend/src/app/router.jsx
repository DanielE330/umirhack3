import { createHashRouter, Navigate } from 'react-router-dom'
import AppLayout from '../layouts/AppLayout.jsx'
import Containers from '../pages/Containers/Containers.jsx'
import Login from '../pages/Login/Login.jsx'
import Overview from '../pages/Overview/Overview.jsx'
import Profiles from '../pages/Profiles/Profiles.jsx'
import Settings from '../pages/Settings/Settings.jsx'
import Traps from '../pages/Traps/Traps.jsx'
import Users from '../pages/Users/Users.jsx'

// Hash-маршруты: центр отдаёт только index.html, поэтому /#/overview открывается и после обновления страницы
export const router = createHashRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Navigate to="/containers" replace /> },
      { path: 'containers', element: <Containers /> },
      { path: 'overview', element: <Overview /> },
      { path: 'traps', element: <Traps /> },
      { path: 'profiles', element: <Profiles /> },
      { path: 'users', element: <Users /> },
      { path: 'settings', element: <Settings /> },
      { path: '*', element: <Navigate to="/containers" replace /> },
    ],
  },
])
