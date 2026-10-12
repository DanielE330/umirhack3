import { useLanguage } from '../../context/language.js'
import { PVE } from '../../lib/model.js'
import { Field } from '../common.jsx'

// Ядра / ОЗУ / диск: значения хранятся строками в родителе (value = { cores, ram, disk })
export default function ResourceFields({ value, onChange }) {
  const { t } = useLanguage()
  const set = (key) => (e) => onChange({ ...value, [key]: e.target.value })
  const num = (key, label, limits) => (
    <Field label={label}>
      <input type="number" min={limits[0]} max={limits[1]} step={1} value={value[key]} onChange={set(key)} aria-label={t(label)} />
    </Field>
  )
  return (
    <>
      <div className="res">
        {num('cores', 'Ядра', PVE.limits.cores)}
        {num('ram', 'ОЗУ, ГБ', PVE.limits.ram)}
        {num('disk', 'Диск, ГБ', PVE.limits.disk)}
      </div>
      <button type="button" className="linkbtn" onClick={() => onChange({ ...PVE.defaults })}>
        {t('Вернуть шаблон 1 ядро / 1 ГБ / 10 ГБ')}
      </button>
    </>
  )
}
