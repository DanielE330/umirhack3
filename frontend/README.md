# Веб-интерфейс HoneyForge

React 19 + Vite + React Router (hash-маршруты). Центр отдаёт сборку `dist/`: страницу — по `/`, файлы — по `/static/*`.

```sh
npm ci
npm run build      # dist/ — её раздаёт центр (в Docker собирается автоматически)
npm run dev        # dev-сервер, /api и WebSocket проксируются на центр (VITE_API_TARGET, по умолчанию http://localhost:4000)
npm run dev:demo   # без центра, на вымышленных данных
npm run lint
```

- `src/pages/` — разделы (Контейнеры, Обзор, Ловушки, Профили, Настройки), `src/components/modals/` — окна.
- `src/lib/api.js` — запросы к центру: cookie-сессия + `X-CSRF-Token`; `src/lib/model.js` — преобразование ответов API.
- `src/i18n/` — переводы: ключ — русская строка, `en.js` — английский.
- `legacy/` — прежняя панель на чистом JS, не собирается и не раздаётся.
