// Якорь заголовка: кириллица сохраняется, остальное — дефисы. Ссылки #якорь ломают hash-роутер,
// поэтому оглавление скроллит скриптом (см. Wiki.jsx), а сам id нужен только как цель.
export const slug = (text) =>
  text.replace(/[`*]/g, '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-+|-+$/g, '')

// Заголовки h2/h3 для оглавления (блоки кода пропускаются, id уникальны)
export function headings(source) {
  const out = []
  const seen = new Map()
  let code = false
  for (const line of source.replace(/\r\n/g, '\n').split('\n')) {
    if (line.startsWith('```')) code = !code
    const m = !code && /^(#{2,3})\s+(.*)$/.exec(line)
    if (!m) continue
    const base = slug(m[2]) || 'section'
    const n = seen.get(base) || 0
    seen.set(base, n + 1)
    out.push({ level: m[1].length, text: m[2].replace(/[`*]/g, ''), id: n ? base + '-' + n : base })
  }
  return out
}

