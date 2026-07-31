import { useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  AuditOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DesktopOutlined,
  FieldTimeOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyOutlined,
  SearchOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Button, Drawer, Layout, Menu, Space, Typography } from 'antd'
import type { MenuProps } from 'antd'

import { useSession } from '../shared/api/queries'

const navItems: MenuProps['items'] = [
  { key: '/overview', icon: <DashboardOutlined />, label: <NavLink to="/overview">总览</NavLink> },
  { key: '/activity', icon: <GlobalOutlined />, label: <NavLink to="/activity">访问态势</NavLink> },
  { key: '/devices', icon: <DesktopOutlined />, label: <NavLink to="/devices">设备识别</NavLink> },
  { key: '/events', icon: <SearchOutlined />, label: <NavLink to="/events">事件检索</NavLink> },
  { key: '/ingest', icon: <DatabaseOutlined />, label: <NavLink to="/ingest">采集诊断</NavLink> },
  { key: '/risks', icon: <SafetyOutlined />, label: <NavLink to="/risks">风险 IP</NavLink> },
  { key: '/review', icon: <FileSearchOutlined />, label: <NavLink to="/review">人工复核</NavLink> },
  { key: '/shadow-runs', icon: <FieldTimeOutlined />, label: <NavLink to="/shadow-runs">影子运行</NavLink> },
  { key: '/audit', icon: <AuditOutlined />, label: <NavLink to="/audit">审计日志</NavLink> },
  {
    key: '/settings/rules',
    icon: <SettingOutlined />,
    label: <NavLink to="/settings/rules">规则配置</NavLink>,
  },
]

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
  const selected = `/${location.pathname.split('/')[1] || 'overview'}`
  const selectedKey = location.pathname.startsWith('/settings') ? '/settings/rules' : selected
  const isMockEnabled = !import.meta.env.PROD && import.meta.env.VITE_ENABLE_MOCKS !== 'false'

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
              <div className="brand-subtitle">防代理/共享上网检测</div>
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
        title="Proxy Sentinel - 防代理检测系统"
      >
        {menu}
      </Drawer>
    </Layout>
  )
}
