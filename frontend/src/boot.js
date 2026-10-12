// Выполняется до создания роутера (импортируется в main.jsx первым).
// Документация доступна по /wiki и на хосте wiki.<домен>: открываем её hash-маршрут.
if ((window.location.pathname === '/wiki' || window.location.hostname.startsWith('wiki.')) && !window.location.hash) {
  window.history.replaceState(null, '', '/#/wiki')
}
