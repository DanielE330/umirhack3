import { createContext, useContext } from 'react'

export const LanguageContext = createContext(null)
// Подписка на смену языка: компонент перерисовывается и берёт свежие строки через t()
export const useLanguage = () => useContext(LanguageContext)
