import { ScrollText } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Events() {
  return (
    <PagePlaceholder
      icon={ScrollText}
      title="Events"
      description="Журнал событий атак с фильтрацией и поиском."
    />
  )
}
