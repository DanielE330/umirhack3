import { Settings as SettingsIcon } from 'lucide-react'
import PagePlaceholder from '../../components/PagePlaceholder.jsx'

export default function Settings() {
  return (
    <PagePlaceholder
      icon={SettingsIcon}
      title="Settings"
      description="Параметры платформы, пользователей и интеграций."
    />
  )
}

