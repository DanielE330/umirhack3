import { createContext, useContext } from 'react'

export const LayoutContext = createContext(null)
// Расположение навигации: 'top' — верхний тулбар, 'side' — боковая панель слева
export const useLayout = () => useContext(LayoutContext)
