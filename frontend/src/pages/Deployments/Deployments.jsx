import { Rocket } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Deployments() {
  return (
    <PagePlaceholder
      icon={Rocket}
      title="Deployments"
      description="Управление развёртыванием экземпляров ловушек на удалённых хостах."
    />
  )
}
