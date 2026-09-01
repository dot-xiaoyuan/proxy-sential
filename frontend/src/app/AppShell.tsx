import { useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  AuditOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DesktopOutlined,
  FieldTimeOutlined,
  GlobalOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyOutlined,
  SearchOutlined,
  SettingOutlined,
  UserOutlined,
	ApartmentOutlined,
	ControlOutlined,
} from '@ant-design/icons'
import { Button, Drawer, Layout, Menu, Space, Typography } from 'antd'
import type { MenuProps } from 'antd'

import { useLogout, useSession } from '../shared/api/queries'
import { LoginPage } from '../pages/LoginPage'
import { AppLoadingState } from '../shared/ui'
import { can } from '../shared/auth/permissions'
import type { Session } from '../shared/api/types'

function buildNavItems(session: Session): MenuProps['items'] {
  const systemChildren: MenuProps['items'] = [
    can(session,'ingest:read') ? {key:'/ingest',icon:<DatabaseOutlined />,label:<NavLink to="/ingest">数据源与采集</NavLink>} : null,
    can(session,'shadow:read') ? {key:'/shadow-runs',icon:<FieldTimeOutlined />,label:<NavLink to="/shadow-runs">影子评估</NavLink>} : null,
    can(session,'audit:read') ? {key:'/audit',icon:<AuditOutlined />,label:<NavLink to="/audit">审计日志</NavLink>} : null,
    can(session,'rules:reload') || can(session,'device-fingerprint-library:update') ? {key:'/settings/rules',icon:<SettingOutlined />,label:<NavLink to="/settings/rules">规则与特征库</NavLink>} : null,
    can(session,'organization:read') ? {key:'/settings/organization',icon:<ApartmentOutlined />,label:<NavLink to="/settings/organization">校区与网络区域</NavLink>} : null,
    can(session,'actions:read') ? {key:'/settings/actions',icon:<ControlOutlined />,label:<NavLink to="/settings/actions">处置网关</NavLink>} : null,
    can(session,'users:manage') ? {key:'/settings/security',icon:<UserOutlined />,label:<NavLink to="/settings/security">权限与校园例外</NavLink>} : null,
  ].filter(Boolean) as MenuProps['items']
  return [
    {key:'/overview',icon:<DashboardOutlined />,label:<NavLink to="/overview">运营工作台</NavLink>},
    can(session,'cases:read') ? {key:'/cases',icon:<SafetyOutlined />,label:<NavLink to="/cases">风险处置</NavLink>} : null,
    can(session,'identity:read') ? {key:'/devices',icon:<DesktopOutlined />,label:<NavLink to="/devices">终端画像</NavLink>} : null,
    can(session,'dpi:read') ? {key:'/activity',icon:<GlobalOutlined />,label:<NavLink to="/activity">网络态势</NavLink>} : null,
    can(session,'events:read') ? {key:'/events',icon:<SearchOutlined />,label:<NavLink to="/events">调查取证</NavLink>} : null,
    {key:'system',icon:<SettingOutlined />,label:'系统管理',children:systemChildren},
  ].filter(Boolean) as MenuProps['items']
}

function SentinelLogo() {
  return (
    <svg className="brand-logo-svg" fill="none" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <path d="M16 3L5 7V14C5 20.5 9.7 26.5 16 29C22.3 26.5 27 20.5 27 14V7L16 3Z" stroke="#0284c7" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" />
      <circle cx="16" cy="15" r="5" stroke="#0ea5e9" strokeWidth="2" />
      <circle cx="16" cy="15" fill="#0284c7" r="2" />
    </svg>
  )
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const location = useLocation()
  const session = useSession()
  const logout = useLogout()
  const selected = `/${location.pathname.split('/')[1] || 'overview'}`
  const selectedKey = location.pathname.startsWith('/settings/') ? location.pathname : selected
  const isMockEnabled = !import.meta.env.PROD && import.meta.env.VITE_ENABLE_MOCKS !== 'false'

  if (session.isLoading) return <AppLoadingState rows={6} />
  if (session.isError || !session.data) return <LoginPage />
	const navItems = buildNavItems(session.data)

  const menu = (
    <Menu
      items={navItems}
      mode="inline"
      selectedKeys={[selectedKey]}
      theme="light"
      onClick={() => setDrawerOpen(false)}
    />
  )

  return (
    <Layout className="app-shell">
      <Layout.Sider
        breakpoint="lg"
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
            <div>
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
        <Layout.Content className="app-content">
          <Outlet />
        </Layout.Content>
      </Layout>
      <Drawer
        className="mobile-nav"
        onClose={() => setDrawerOpen(false)}
        open={drawerOpen}
        placement="left"
        size="default"
        title="Proxy Sentinel - 高校网络风险运营平台"
      >
        {menu}
      </Drawer>
    </Layout>
  )
}
