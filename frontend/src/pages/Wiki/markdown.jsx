// Минимальный рендер Markdown без сторонних библиотек.
// Поддерживает то, что есть в WIKI.md: заголовки, абзацы, списки, таблицы, блоки кода, цитаты,
// разделители, `код`, **жирный** и ссылки. Всё выводится как элементы React, поэтому HTML из текста не исполняется.

// Ссылки разрешены только http(s), относительные и якорные. javascript: и другие схемы отбрасываются.
const SAFE_HREF = /^(https?:\/\/|\/|#|\.\.?\/)/i

function inline(text, keyBase = 'i') {
  const out = []
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^)\s]+)\)/g
  let last = 0
  let m
  let n = 0
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const key = keyBase + '-' + n++
    if (m[1] !== undefined) {
      out.push(<code key={key}>{m[1]}</code>)
    } else if (m[2] !== undefined) {
      out.push(<strong key={key}>{m[2]}</strong>)
    } else if (SAFE_HREF.test(m[4])) {
      const external = /^https?:\/\//i.test(m[4])
      out.push(
        <a key={key} href={m[4]} target={external ? '_blank' : undefined} rel={external ? 'noopener noreferrer' : undefined}>
          {m[3]}
        </a>,
      )
    } else {
      out.push(m[3])
    }
    last = re.lastIndex
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

const cells = (row) => row.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim())

export default function Markdown({ source }) {
  const lines = source.replace(/\r\n/g, '\n').split('\n')
  const blocks = []
  let i = 0
  let k = 0
  const key = () => 'b' + k++

  // строка начинает новый блок: тогда абзац на ней заканчивается
  const startsBlock = (l) =>
    /^(#{1,6}\s|```|>|---+\s*$|\s*[-*]\s|\s*\d+\.\s|\|)/.test(l)

  while (i < lines.length) {
    const line = lines[i]

    if (!line.trim()) {
      i++
      continue
    }

    if (line.startsWith('```')) {
      const code = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) code.push(lines[i++])
      i++
      blocks.push(<pre key={key()}><code>{code.join('\n')}</code></pre>)
      continue
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line)
    if (heading) {
      const Tag = 'h' + heading[1].length
      blocks.push(<Tag key={key()}>{inline(heading[2])}</Tag>)
      i++
      continue
    }

    if (/^---+\s*$/.test(line)) {
      blocks.push(<hr key={key()} />)
      i++
      continue
    }

    if (line.startsWith('>')) {
      const quote = []
      while (i < lines.length && lines[i].startsWith('>')) quote.push(lines[i++].replace(/^>\s?/, ''))
      blocks.push(<blockquote key={key()}><p>{inline(quote.join(' '))}</p></blockquote>)
      continue
    }

    if (line.trim().startsWith('|') && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1])) {
      const head = cells(line)
      i += 2
      const rows = []
      while (i < lines.length && lines[i].trim().startsWith('|')) rows.push(cells(lines[i++]))
      blocks.push(
        <div className="wiki-table" key={key()}>
          <table>
            <thead>
              <tr>{head.map((h, c) => <th key={c}>{inline(h, 'th' + c)}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri}>{r.map((c, ci) => <td key={ci}>{inline(c, 'r' + ri + 'c' + ci)}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>,
      )
      continue
    }

    const bullet = /^\s*[-*]\s+(.*)$/
    const numbered = /^\s*\d+\.\s+(.*)$/
    if (bullet.test(line) || numbered.test(line)) {
      const ordered = numbered.test(line)
      const re = ordered ? numbered : bullet
      const items = []
      while (i < lines.length && re.test(lines[i])) {
        items.push(re.exec(lines[i++])[1])
        // продолжение пункта: строка с отступом, которая не начинает новый пункт
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !bullet.test(lines[i]) && !numbered.test(lines[i])) {
          items[items.length - 1] += ' ' + lines[i++].trim()
        }
      }
      const List = ordered ? 'ol' : 'ul'
      blocks.push(<List key={key()}>{items.map((x, ii) => <li key={ii}>{inline(x, 'li' + ii)}</li>)}</List>)
      continue
    }

    // обычный абзац: строки до пустой строки или нового блока
    const para = []
    while (i < lines.length && lines[i].trim() && (para.length === 0 || !startsBlock(lines[i]))) para.push(lines[i++].trim())
    blocks.push(<p key={key()}>{inline(para.join(' '))}</p>)
  }

  return <>{blocks}</>
}
