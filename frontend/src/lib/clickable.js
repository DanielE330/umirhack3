// Делает не-кнопку кликабельной с клавиатуры (Enter / Space)
export const clickable = (handler) => ({
  tabIndex: 0,
  onClick: handler,
  onKeyDown: (e) => {
    if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault()
      handler(e)
    }
  },
})
