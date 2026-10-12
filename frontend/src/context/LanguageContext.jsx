import { useCallback, useEffect, useMemo, useState } from 'react'
import { getLang, getLocale, setLang as applyLang, t } from '../i18n/translations.js'
import { LanguageContext } from './language.js'

// Язык интерфейса: RU / EN. Выбор хранится в localStorage (ключ lang) и применяется без перезагрузки.
export default function LanguageProvider({ children }) {
  const [lang, setLangState] = useState(getLang)

  const setLang = useCallback((next) => {
    applyLang(next) // сначала переключаем модуль переводов, потом перерисовываем подписчиков
    setLangState(next)
  }, [])

  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const value = useMemo(() => ({ lang, setLang, t, locale: getLocale() }), [lang, setLang])
  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>
}
