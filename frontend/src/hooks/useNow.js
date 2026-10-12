import { useEffect, useState } from 'react'

// Текущее время, обновляется раз в интервал: для «на связи: N с назад» без перерисовки всей страницы
export function useNow(ms = 1000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}
