/**
 * variant: 'primary' | 'secondary' | 'ghost' | 'danger'
 * size: 'md' | 'sm'
 * icon: компонент иконки lucide; без children кнопка становится иконочной
 * (тогда обязателен aria-label).
 */
export default function Button({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  type = 'button',
  className = '',
  children,
  ...rest
}) {
  const classes = [
    'btn',
    `btn--${variant}`,
    size === 'sm' && 'btn--sm',
    Icon && !children && 'btn--icon',
    className,
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <button type={type} className={classes} {...rest}>
      {Icon && <Icon size={size === 'sm' ? 14 : 18} aria-hidden="true" />}
      {children}
    </button>
  )
}
