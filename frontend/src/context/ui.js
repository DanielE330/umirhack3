import { createContext, useContext } from 'react'

export const UiContext = createContext(null)
export const useUi = () => useContext(UiContext)
