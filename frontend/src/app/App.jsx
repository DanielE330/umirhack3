import { RouterProvider } from 'react-router-dom'
import AuthProvider from '../context/AuthProvider.jsx'
import UiProvider from '../context/UiProvider.jsx'
import { router } from './router.jsx'

export default function App() {
  return (
    <UiProvider>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </UiProvider>
  )
}
