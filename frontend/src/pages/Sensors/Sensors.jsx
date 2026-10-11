import { Radar } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Sensors() {
  return (
    <PagePlaceholder
      icon={Radar}
      title="Sensors"
      description="Список ловушек (сенсоров) на удалённых хостах, их состояние и связь с центром."
    />
  )
}
