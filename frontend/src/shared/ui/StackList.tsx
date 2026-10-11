import type { ReactNode } from 'react'

/**
 * antd 6 已弃用 List 组件，这里用项目自有样式类（ps-list-*）承接既有用法：
 * 列表容器、列表项、操作区与 Meta（标题 + 描述）。
 * 结构保持与 antd List 一致，样式统一收敛在 src/index.css。
 */

type StackListProps<T> = {
	items: readonly T[]
	renderItem: (item: T, index: number) => ReactNode
	empty?: ReactNode
	className?: string
	itemKey?: (item: T, index: number) => string
}

export function StackList<T>({ items, renderItem, empty, className, itemKey }: StackListProps<T>) {
	if (items.length === 0) {
		// className 必须同时作用于空态容器，否则 mobile-only 之类的可见性约束会失效
		return <div className={className ? `ps-list-empty ${className}` : 'ps-list-empty'}>{empty ?? '暂无数据'}</div>
	}
	return (
		<div className={className ? `ps-list ${className}` : 'ps-list'}>
			{items.map((item, index) => (
				<div className="ps-list-item" key={itemKey ? itemKey(item, index) : index}>
					{renderItem(item, index)}
				</div>
			))}
		</div>
	)
}

type StackListItemProps = {
	meta?: ReactNode
	actions?: ReactNode
	children?: ReactNode
}

export function StackListItem({ meta, actions, children }: StackListItemProps) {
	return (
		<>
			<div className="ps-list-item-main">
				{meta}
				{children}
			</div>
			{actions}
		</>
	)
}

type StackListItemMetaProps = {
	title?: ReactNode
	description?: ReactNode
}

export function StackListItemMeta({ title, description }: StackListItemMetaProps) {
	return (
		<div className="ps-list-item-meta">
			<div className="ps-list-item-meta-content">
				{title !== undefined && <div className="ps-list-item-meta-title">{title}</div>}
				{description !== undefined && <div className="ps-list-item-meta-description">{description}</div>}
			</div>
		</div>
	)
}

type StackListActionsProps = {
	children: ReactNode
}

export function StackListActions({ children }: StackListActionsProps) {
	return <div className="ps-list-item-action">{children}</div>
}
