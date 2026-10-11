/**
 * title: заголовок секции (если не задан, шапка не рисуется)
 * actions: элементы справа в шапке
 * flush: убрать внутренние отступы тела (например, для таблиц)
 */
export default function Panel({ title, actions, flush = false, className = '', children }) {
  return (
    <section className={`panel${flush ? ' panel--flush' : ''} ${className}`.trim()}>
      {(title || actions) && (
        <header className="panel__header">
          <h2 className="panel__title">{title}</h2>
          {actions}
        </header>
      )}
      <div className="panel__body">{children}</div>
    </section>
  )
}
