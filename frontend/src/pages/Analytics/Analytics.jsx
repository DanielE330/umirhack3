import { ChartColumn } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Analytics() {
  return (
    <PagePlaceholder
      icon={ChartColumn}
      title="Analytics"
      description="Аналитика атак: источники, цели, динамика и распределения."
    />
  )
}
