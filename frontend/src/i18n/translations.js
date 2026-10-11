// Переводы интерфейса. Ключ — русская исходная строка: в русском режиме t() отдаёт её как есть,
// в английском берёт перевод из en.js. Если перевода нет, остаётся русский текст.
// Плейсхолдеры {name} подставляются из объекта vars.
import en from './en.js'

const STORAGE_KEY = 'lang'
let current = 'ru'
try {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'en' || saved === 'ru') current = saved
} catch {
  /* localStorage недоступен (приватный режим): остаёмся на русском */
}

export const getLang = () => current
export const getLocale = () => (current === 'en' ? 'en-GB' : 'ru-RU')

export function setLang(lang) {
  current = lang
  try {
    localStorage.setItem(STORAGE_KEY, lang)
  } catch {
    /* не сохранили — язык всё равно применён до перезагрузки */
  }
}

export function t(key, vars) {
  let s = current === 'en' && en[key] !== undefined ? en[key] : key
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m))
  return s
}
