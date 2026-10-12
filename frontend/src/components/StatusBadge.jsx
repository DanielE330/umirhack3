const DEFAULT_LABELS = {
  online: 'Online',
  warning: 'Warning',
  critical: 'Critical',
  offline: 'Offline',
}

/**
 * status: 'online' | 'warning' | 'critical' | 'offline'
 * label: необязательный текст (по умолчанию — название статуса).
 * Текстовая метка есть всегда: статус не передаётся одним цветом.
 */
export default function StatusBadge({ status = 'offline', label }) {
  const key = status in DEFAULT_LABELS ? status : 'offline'

  return (
    <span className={`status status--${key}`}>
      <span className="status__dot" aria-hidden="true" />
      <span className="status__text">{label ?? DEFAULT_LABELS[key]}</span>
    </span>
  )
}
