import { RouterProvider } from 'react-router-dom'
import AuthProvider from '../context/AuthProvider.jsx'
import LanguageProvider from '../context/LanguageContext.jsx'
import LayoutProvider from '../context/LayoutContext.jsx'
import UiProvider from '../context/UiProvider.jsx'
import { router } from './router.jsx'

export default function App() {
  return (
    <LanguageProvider>
      <LayoutProvider>
        <UiProvider>
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
        </UiProvider>
      </LayoutProvider>
    </LanguageProvider>
  )
}
