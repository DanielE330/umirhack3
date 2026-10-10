import { Bell } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Alerts() {
  return (
    <PagePlaceholder
      icon={Bell}
      title="Alerts"
      description="Оповещения о критичных событиях и состоянии инфраструктуры."
    />
  )
}
