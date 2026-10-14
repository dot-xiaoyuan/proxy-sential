import type { FourKDirectoryItem } from './api'

export type DirectoryTreeNode = { value: string; key: string; title: string; children?: DirectoryTreeNode[] }

/**
 * Groups arrive as a flat id/parent_id list. Render the real organisational
 * hierarchy when the northbound catalog supplied one, and fall back to a flat
 * list when this site only has identity observations. An entry without a name is
 * labelled as a numbered group so a bare id is never mistaken for a real name.
 */
export function groupTreeData(items: FourKDirectoryItem[]): DirectoryTreeNode[] {
  const nodes = new Map<string, DirectoryTreeNode>()
  for (const item of items) {
    nodes.set(item.id, { value: item.id, key: item.id, title: item.name || `组 ${item.id}` })
  }
  const roots: DirectoryTreeNode[] = []
  for (const item of items) {
    const node = nodes.get(item.id)!
    const parent = item.parent_id ? nodes.get(item.parent_id) : undefined
    if (parent && parent !== node) {
      parent.children = parent.children ?? []
      parent.children.push(node)
    } else {
      roots.push(node)
    }
  }
  return roots
}
