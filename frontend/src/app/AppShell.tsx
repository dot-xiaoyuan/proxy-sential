import { OperationTaskProgress } from '../shared/ui/OperationTaskProgress'
import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  DashboardOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Button, Drawer, Layout, Menu, Space, Typography } from 'antd'
import type { MenuProps } from 'antd'

import { useLogout, useSession } from '../shared/api/queries'
import { LoginPage } from '../pages/LoginPage'
import { AppLoadingState } from '../shared/ui'
import { can } from '../shared/auth/permissions'
import { routeOwner, routePermission, visibleNavigation } from './navigation'
import { Alert } from 'antd'
import type { Session } from '../shared/api/types'

function buildNavItems(session: Session): MenuProps['items'] {
  return visibleNavigation(session).map(group => group.key === 'workbench' ? {
    key: group.items[0].key, icon: <DashboardOutlined />, label: <NavLink to={group.items[0].to}>{group.title}</NavLink>
  } : {key:group.key,label:group.title,icon:<SettingOutlined />,children:group.items.map(entry=>({key:entry.key,label:<NavLink to={entry.to}>{entry.title}</NavLink>}))})
}

function SentinelLogo() {
  return (
    <svg aria-label="Proxy Sentinel" role="img" className="brand-logo-svg" fill="none" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <path d="M16 3L5 7V14C5 20.5 9.7 26.5 16 29C22.3 26.5 27 20.5 27 14V7L16 3Z" stroke="#0284c7" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" />
      <circle cx="16" cy="15" r="5" stroke="#0ea5e9" strokeWidth="2" />
      <circle cx="16" cy="15" fill="#0284c7" r="2" />
    </svg>
  )
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const contentRef = useRef<HTMLElement | null>(null)
  const location = useLocation()
  const session = useSession()
  const logout = useLogout()
  const owner = routeOwner(location.pathname,location.search)
  const [openKeys,setOpenKeys] = useState<string[]>([])
  useEffect(()=>{if(owner && owner.group.key !== 'workbench')setOpenKeys(keys=>[...new Set([...keys,owner.group.key])])},[owner?.group.key])
  const isMockEnabled = !import.meta.env.PROD && import.meta.env.VITE_ENABLE_MOCKS !== 'false'

  useEffect(() => {
    contentRef.current?.scrollTo({ top: 0, behavior: 'auto' })
  }, [location.pathname, location.search])

  if (session.isLoading) return <AppLoadingState rows={6} />
  if (session.isError || !session.data) return <LoginPage />
	const navItems = buildNavItems(session.data)

  const menu = (
    <Menu
      inlineIndent={16}
      items={navItems}
      mode="inline"
      selectedKeys={owner ? [owner.entry.key] : []}
      openKeys={openKeys}
      onOpenChange={setOpenKeys}
      theme="light"
      onClick={() => setDrawerOpen(false)}
    />
  )

  return (
    <Layout className="app-shell">
      <Layout.Sider
        className="app-sider"
        collapsed={collapsed}
        collapsible
        onCollapse={setCollapsed}
        theme="light"
        trigger={null}
        width={232}
      >
        <div className="brand">
          <SentinelLogo />
          {!collapsed && (
            <div className="brand-copy">
              <div className="brand-title">Proxy Sentinel</div>
              <div className="brand-subtitle">高校网络风险运营平台</div>
            </div>
          )}
        </div>
        {menu}
      </Layout.Sider>
      <Layout className="app-main-layout">
        <Layout.Header className="app-header">
          <Space>
            <Button
              aria-label={collapsed ? '展开导航' : '收起导航'}
              className="desktop-menu-button"
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => setCollapsed(!collapsed)}
              type="text"
            />
            <Button
              aria-label="打开导航"
              className="mobile-menu-button"
              icon={<MenuUnfoldOutlined />}
              onClick={() => setDrawerOpen(true)}
              type="text"
            />
            {isMockEnabled && <span className="mock-badge">Mock API Active</span>}
          </Space>
          <Space size="middle">
            <div className="user-session-badge">
              <UserOutlined className="text-primary-color" />
              <Typography.Text strong className="font-size-md">
                {session.data?.user.name ?? '加载中...'}
              </Typography.Text>
              <Typography.Text type="secondary" className="font-size-sm">
                ({session.data?.role ?? 'guest'})
              </Typography.Text>
              <Button loading={logout.isPending} onClick={() => logout.mutate()} size="small" type="text">退出</Button>
            </div>
          </Space>
        </Layout.Header>
        <Layout.Content className="app-content" ref={contentRef}>
          <OperationTaskProgress />
          {!routePermission(location.pathname,location.search) || can(session.data,routePermission(location.pathname,location.search)!) ? <Outlet /> : <Alert showIcon type="warning" title="没有访问权限" description="当前账号无权读取此功能，请联系管理员调整权限。" />}
        </Layout.Content>
      </Layout>
      <Drawer
        rootClassName="mobile-nav"
        onClose={() => setDrawerOpen(false)}
        open={drawerOpen}
        placement="left"
        title="Proxy Sentinel"
        size={320}
      >
        {menu}
      </Drawer>
    </Layout>
  )
}
