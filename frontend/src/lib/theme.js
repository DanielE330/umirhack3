// Тема интерфейса: тёмная («медовая», по умолчанию) или светлая. Хранится в браузере (ключ theme),
// применяется атрибутом data-theme на <html> — токены цветов в styles/variables.css.
const KEY = 'theme'

export function getTheme() {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'light' || v === 'dark') return v
  } catch {
    /* localStorage недоступен (приватный режим): тёмная тема */
  }
  return 'dark'
}

export function applyTheme(theme) {
  document.documentElement.dataset.theme = theme
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    /* не сохранили — тема действует до перезагрузки */
  }
}
