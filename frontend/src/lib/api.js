// Клиент API центра: cookie-сессия + CSRF-токен в заголовке (как в исходной панели)
import { t } from '../i18n/translations.js'
import { DEMO, demoApi } from './demo.js'

let csrf = ''
let onUnauthorized = () => {}

export const setCsrf = (value) => {
  csrf = value || ''
}
export const setUnauthorizedHandler = (fn) => {
  onUnauthorized = fn
}

export async function api(path, { method = 'GET', body, auth = true } = {}) {
  if (DEMO) return demoApi(path, method, body)
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 401 && auth) {
    onUnauthorized()
    throw new Error(t('Сессия истекла'))
  }
  if (res.status === 204) return null
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const d = data.detail
    throw new Error(
      typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join('; ') : t('Ошибка {status}', { status: res.status }),
    )
  }
  return data
}
