import { useEffect, useRef } from 'react'

const SHOW_DELAY = 1000 // подсказка появляется, когда курсор постоял на элементе секунду
const HIDE_DELAY = 200 // и не исчезает мгновенно при коротком уходе курсора

// Быстрые подсказки в стиле панели: любой элемент с data-tip показывает их при наведении и фокусе с клавиатуры.
export default function Tooltips() {
  const tipRef = useRef(null)

  useEffect(() => {
    const tip = tipRef.current
    let current = null
    let timer = 0
    let exit = 0
    const find = (n) => (n && n.closest ? n.closest('[data-tip]') : null)

    const show = (node) => {
      const text = node.dataset.tip
      if (!text) return
      current = node
      tip.textContent = text
      node.setAttribute('aria-describedby', 'tip')
      tip.classList.remove('on')
      tip.style.left = '0px'
      tip.style.top = '0px'
      const r = node.getBoundingClientRect()
      const pad = 8
      const w = tip.offsetWidth
      const h = tip.offsetHeight
      let top = r.top - h - pad
      if (top < pad) top = r.bottom + pad
      const left = Math.min(Math.max(pad, r.left + r.width / 2 - w / 2), innerWidth - w - pad)
      tip.style.left = left + 'px'
      tip.style.top = top + 'px'
      requestAnimationFrame(() => tip.classList.add('on'))
    }
    const hide = () => {
      clearTimeout(timer)
      clearTimeout(exit)
      if (current) current.removeAttribute('aria-describedby')
      current = null
      tip.classList.remove('on')
    }
    const onOver = (e) => {
      const n = find(e.target)
      clearTimeout(exit)
      if (n === current) return
      clearTimeout(timer)
      if (n) {
        if (current) hide() // соседняя подсказка: старую скрываем сразу
        timer = setTimeout(() => show(n), SHOW_DELAY)
      } else if (current) {
        exit = setTimeout(hide, HIDE_DELAY)
      }
    }
    const onFocusIn = (e) => {
      const n = find(e.target)
      hide()
      if (n && e.target.matches(':focus-visible')) show(n)
    }
    const onKey = (e) => {
      if (e.key === 'Escape') hide()
    }

    document.addEventListener('mouseover', onOver)
    document.addEventListener('focusin', onFocusIn)
    document.addEventListener('focusout', hide)
    document.addEventListener('mousedown', hide)
    document.addEventListener('keydown', onKey)
    addEventListener('scroll', hide, true)
    return () => {
      hide()
      document.removeEventListener('mouseover', onOver)
      document.removeEventListener('focusin', onFocusIn)
      document.removeEventListener('focusout', hide)
      document.removeEventListener('mousedown', hide)
      document.removeEventListener('keydown', onKey)
      removeEventListener('scroll', hide, true)
    }
  }, [])

  return <div ref={tipRef} className="tip" id="tip" role="tooltip" />
}
