import { describe, expect, it } from 'vitest'
import { groupTreeData } from './directoryTree'

describe('groupTreeData', () => {
  it('restores the northbound hierarchy from parent ids', () => {
    const tree = groupTreeData([
      { id: '1', name: '信息工程学院' },
      { id: '12', name: '网络工程系', parent_id: '1' },
      { id: '13', name: '软件工程系', parent_id: '1' },
      { id: '2', name: '教务处' },
    ])
    expect(tree.map(node => node.title)).toEqual(['信息工程学院', '教务处'])
    expect(tree[0].children?.map(node => node.title)).toEqual(['网络工程系', '软件工程系'])
    expect(tree[0].children?.[0].value).toBe('12')
  })

  it('labels an unnamed identity observation as a numbered group', () => {
    const tree = groupTreeData([{ id: '208' }])
    expect(tree).toHaveLength(1)
    expect(tree[0].title).toBe('组 208')
  })

  it('keeps a flat directory flat', () => {
    const tree = groupTreeData([{ id: 'a' }, { id: 'b' }])
    expect(tree.map(node => node.value)).toEqual(['a', 'b'])
    expect(tree.every(node => node.children === undefined)).toBe(true)
  })

  it('survives a dangling parent reference', () => {
    const tree = groupTreeData([{ id: '12', name: '孤儿组', parent_id: '99' }])
    expect(tree.map(node => node.value)).toEqual(['12'])
  })
})
