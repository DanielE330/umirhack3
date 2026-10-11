import {
  Activity,
  Bell,
  ChartColumn,
  FileDown,
  Layers,
  LayoutDashboard,
  Radar,
  Rocket,
  ScrollText,
  Settings,
} from 'lucide-react'

export const NAV_GROUPS = [
  {
    title: 'Monitoring',
    items: [
      { to: '/overview', label: 'Overview', icon: LayoutDashboard },
      { to: '/telemetry', label: 'Telemetry', icon: Activity },
      { to: '/events', label: 'Events', icon: ScrollText },
      { to: '/alerts', label: 'Alerts', icon: Bell },
    ],
  },
  {
    title: 'Management',
    items: [
      { to: '/sensors', label: 'Sensors', icon: Radar },
      { to: '/profiles', label: 'Profiles', icon: Layers },
      { to: '/deployments', label: 'Deployments', icon: Rocket },
    ],
  },
  {
    title: 'Analysis',
    items: [
      { to: '/analytics', label: 'Analytics', icon: ChartColumn },
      { to: '/ioc', label: 'IoC / Export', icon: FileDown },
    ],
  },
  {
    title: 'System',
    items: [{ to: '/settings', label: 'Settings', icon: Settings }],
  },
]
