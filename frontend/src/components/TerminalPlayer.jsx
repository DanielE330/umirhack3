import React, { useState, useEffect, useRef } from 'react'

export default function TerminalPlayer({ commands = [], sessionId = '' }) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)
  const [speed, setSpeed] = useState(1) // 1x, 2x, 5x
  const [displayedText, setDisplayedText] = useState('')
  const terminalEndRef = useRef(null)

  useEffect(() => {
    if (commands.length > 0) {
      setCurrentIndex(0)
      setDisplayedText('')
      setIsPlaying(false)
    }
  }, [commands])

  useEffect(() => {
    let timer = null
    if (isPlaying && currentIndex < commands.length) {
      const delay = Math.max(300, 1200 / speed)
      timer = setTimeout(() => {
        setCurrentIndex((prev) => prev + 1)
      }, delay)
    } else if (currentIndex >= commands.length) {
      setIsPlaying(false)
    }
    return () => clearTimeout(timer)
  }, [isPlaying, currentIndex, commands.length, speed])

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollTop = terminalEndRef.current.scrollHeight
    }
  }, [currentIndex, displayedText])

  const togglePlay = () => {
    if (currentIndex >= commands.length) {
      setCurrentIndex(0)
    }
    setIsPlaying((prev) => !prev)
  }

  const handleSeek = (e) => {
    const idx = parseInt(e.target.value, 10)
    setCurrentIndex(idx)
    setIsPlaying(false)
  }

  const shownCommands = commands.slice(0, currentIndex)

  return (
    <div
      style={{
        marginTop: '0.9rem',
        borderRadius: '8px',
        overflow: 'hidden',
        border: '1px solid rgba(255, 255, 255, 0.12)',
        background: '#0a0d14',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.45)',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      }}
    >
      {/* Terminal Titlebar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '6px 12px',
          background: '#161b26',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          fontSize: '0.75rem',
          color: '#8b949e',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ff5f56', display: 'inline-block' }} />
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ffbd2e', display: 'inline-block' }} />
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#27c93f', display: 'inline-block' }} />
          <span style={{ marginLeft: 8, fontWeight: 500, color: '#c9d1d9' }}>
            web-tty · {sessionId ? sessionId.slice(0, 12) : 'session'} (bash)
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '0.7rem', color: '#58a6ff' }}>
            Asciinema Replay: {currentIndex}/{commands.length}
          </span>
        </div>
      </div>

      {/* Terminal Output Screen */}
      <div
        ref={terminalEndRef}
        style={{
          padding: '12px 14px',
          minHeight: '130px',
          maxHeight: '220px',
          overflowY: 'auto',
          fontSize: '0.82rem',
          lineHeight: '1.5',
          color: '#e6edf3',
        }}
      >
        <div style={{ color: '#6e7681', marginBottom: 6, fontSize: '0.74rem' }}>
          # Connected to fake-shell (Ubuntu 22.04 LTS x86_64). Deception logging active.
        </div>
        {shownCommands.map((cmd, i) => (
          <div key={i} style={{ marginBottom: 4, wordBreak: 'break-all' }}>
            <span style={{ color: '#7ee787', fontWeight: 600 }}>root@dmz-target:~# </span>
            <span style={{ color: '#ff7b72' }}>{cmd}</span>
          </div>
        ))}
        {currentIndex < commands.length && (
          <div style={{ wordBreak: 'break-all' }}>
            <span style={{ color: '#7ee787', fontWeight: 600 }}>root@dmz-target:~# </span>
            <span style={{ animation: 'blink 1s infinite', borderRight: '2px solid #58a6ff' }}>&nbsp;</span>
          </div>
        )}
        {currentIndex >= commands.length && commands.length > 0 && (
          <div style={{ color: '#8b949e', marginTop: 6, fontSize: '0.74rem' }}>
            # [Process completed. Connection closed by foreign host]
          </div>
        )}
      </div>

      {/* Playback Controls Footer */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '8px 12px',
          background: '#111622',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        }}
      >
        <button
          type="button"
          onClick={togglePlay}
          style={{
            background: isPlaying ? '#da3633' : '#238636',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            padding: '3px 10px',
            fontSize: '0.75rem',
            cursor: 'pointer',
            fontWeight: 600,
          }}
        >
          {isPlaying ? '⏸ Пауза' : currentIndex >= commands.length ? '🔄 Заново' : '▶ Воспроизвести'}
        </button>

        <input
          type="range"
          min="0"
          max={commands.length}
          value={currentIndex}
          onChange={handleSeek}
          style={{
            flex: 1,
            cursor: 'pointer',
            accentColor: '#58a6ff',
          }}
        />

        <div style={{ display: 'flex', gap: '4px' }}>
          {[1, 2, 5].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s)}
              style={{
                background: speed === s ? '#388bfd33' : 'transparent',
                border: speed === s ? '1px solid #58a6ff' : '1px solid rgba(255,255,255,0.1)',
                color: speed === s ? '#58a6ff' : '#8b949e',
                borderRadius: '3px',
                padding: '2px 6px',
                fontSize: '0.7rem',
                cursor: 'pointer',
              }}
            >
              {s}x
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
