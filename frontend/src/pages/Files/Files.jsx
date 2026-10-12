import { useCallback, useEffect, useState } from 'react'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { fmtDateTime } from '../../lib/model.js'

const KINDS = { upload: 'загрузка', write: 'запись', download: 'скачивание' }

// Файлы, которые атакующие загрузили или записали на ловушки: хэш SHA-256 и (если сохранено) содержимое для анализа.
export default function Files() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const [items, setItems] = useState(null)

  const load = useCallback(async () => {
    try {
      setItems((await api('/api/artifacts')).items)
    } catch (e) {
      showToast(e.message, true)
    }
  }, [showToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- загрузка списка при открытии страницы
    load()
    const timer = setInterval(load, 15000)
    return () => clearInterval(timer)
  }, [load])

  const copy = async (sha) => {
    try {
      await navigator.clipboard.writeText(sha)
      showToast(t('Хэш скопирован'))
    } catch {
      showToast(t('Не удалось скопировать: выделите текст вручную'), true)
    }
  }

  return (
    <section>
      <p className="lead">
        {t('Файлы, которые атакующие загрузили (SFTP/scp) или записали в консоли. Хэш считается по всему файлу, содержимое хранится до 64 КБ. Файл опасен: скачивайте только для анализа в изолированной среде.')}
      </p>
      <div className="card">
        <table className="rows">
          <thead>
            <tr>
              <th>{t('Файл')}</th><th>{t('Тип')}</th><th>SHA-256</th><th>{t('Размер')}</th><th>{t('Ловушка')}</th>
              <th>{t('Источник')}</th><th>{t('Раз')}</th><th>{t('Последний раз')}</th><th />
            </tr>
          </thead>
          <tbody>
            {items && items.map((a) => (
              <tr key={a.sha256}>
                <td className="m">{a.name || '—'}</td>
                <td>{t(KINDS[a.kind] || a.kind)}</td>
                <td className="m"><button type="button" className="ghost small" data-tip={t('Скопировать хэш целиком')} onClick={() => copy(a.sha256)}>{a.sha256.slice(0, 16)}…</button></td>
                <td className="m">{a.size} B</td>
                <td>{a.trap}</td>
                <td className="m">{a.src_ip}</td>
                <td>{a.seen_count}</td>
                <td className="m">{fmtDateTime(Date.parse(a.last_seen))}</td>
                <td>{a.has_content
                  ? <a className="btn small" href={'/api/artifacts/' + a.sha256 + '/download'}>{t('Скачать')}</a>
                  : <span className="hint">{t('нет содержимого')}</span>}</td>
              </tr>
            ))}
            {items && !items.length && <tr><td colSpan={9} className="empty">{t('Файлов пока нет')}</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
