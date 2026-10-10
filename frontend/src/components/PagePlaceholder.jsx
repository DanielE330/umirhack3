import PageHeader from './PageHeader.jsx'
import Panel from './Panel.jsx'
import StatusBadge from './StatusBadge.jsx'

export default function PagePlaceholder({ icon: Icon, title, description }) {
  return (
    <>
      <PageHeader title={title} description={description} />
      <Panel>
        <div className="placeholder">
          <span className="placeholder__icon">
            <Icon size={22} aria-hidden="true" />
          </span>
          <StatusBadge status="offline" label="Подготовлено к реализации" />
          <p className="placeholder__text">
            Раздел появится на следующем этапе разработки. Сейчас доступен только каркас страницы.
          </p>
        </div>
      </Panel>
    </>
  )
}
