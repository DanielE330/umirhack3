import { Activity } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Telemetry() {
  return (
    <PagePlaceholder
      icon={Activity}
      title="Telemetry"
      description="Телеметрия ловушек и состояние каналов связи в реальном времени."
    />
  )
}
