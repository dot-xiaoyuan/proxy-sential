import type { ReactNode } from 'react'

interface AppFactBarProps {
  /** One fact per item. Keep each item to a single short clause. */
  items: ReactNode[]
  /** Accessible name for the strip, e.g. the page it explains. */
  label?: string
  className?: string
}

/**
 * Compact fact strip for page-level semantics.
 *
 * This replaces the prose Alert banner that used to sit above list pages: the
 * same information, stated as discrete facts an operator acts on, in the same
 * muted register as the connector cards on the integrations page. Anything that
 * reports a real error, a risk conflict or a current execution state must keep
 * using Alert so it stays visually louder than this strip.
 */
export function AppFactBar({ items, label, className }: AppFactBarProps) {
  const visible = items.filter(Boolean)
  if (!visible.length) return null
  return (
    <ul className={className ? `app-fact-bar ${className}` : 'app-fact-bar'} aria-label={label}>
      {visible.map((item, index) => (
        <li className="app-fact-bar-item" key={index}>
          {item}
        </li>
      ))}
    </ul>
  )
}
