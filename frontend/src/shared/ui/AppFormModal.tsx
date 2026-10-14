import type { ReactNode } from 'react'
import { Modal } from 'antd'

interface AppFormModalProps {
  title: ReactNode
  open: boolean
  onCancel: () => void
  children: ReactNode
  footer?: ReactNode
  okText?: ReactNode
  cancelText?: ReactNode
  onOk?: () => void
  /** Desktop dialog width. Small screens always use the full-height sheet. */
  width?: number
  confirmLoading?: boolean
  destroyOnHidden?: boolean
  forceRender?: boolean
  className?: string
}

/**
 * Configuration form shell for the operations console.
 *
 * Below 560px the dialog becomes a full-height sheet with a sticky header and a
 * sticky footer, so a long form has exactly one scroll container and the primary
 * action stays reachable. The always-visible header and footer matter more than
 * matching the desktop layout on a phone: the previous centred dialog nested a
 * scroll area inside the page and pushed the save button out of reach.
 *
 * Wider viewports keep the centred dialog with an internally scrolling body.
 * All layout lives in `.app-form-modal` in src/index.css; no inline styles.
 *
 * The content is unmounted on close by default. Keeping it mounted leaves antd's
 * submit spinner in the DOM: the button hides while its loading icon is still
 * animating out, so the icon never unmounts and the button's accessible name
 * stays "loading …" for the rest of the session.
 */
export function AppFormModal({
  title,
  open,
  onCancel,
  children,
  footer,
  okText,
  cancelText,
  onOk,
  width,
  confirmLoading,
  destroyOnHidden = true,
  forceRender,
  className,
}: AppFormModalProps) {
  return (
    <Modal
      className={className ? `app-form-modal ${className}` : 'app-form-modal'}
      title={title}
      open={open}
      onCancel={onCancel}
      footer={footer}
      okText={okText}
      cancelText={cancelText}
      onOk={onOk}
      width={width}
      confirmLoading={confirmLoading}
      destroyOnHidden={destroyOnHidden}
      forceRender={forceRender}
    >
      {children}
    </Modal>
  )
}
