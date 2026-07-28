import { useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  AuditOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  FieldTimeOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Button, Drawer, Layout, Menu, Space, Tag, Typography } from 'antd'
import type { MenuProps } from 'antd'

import { useSession } from '../shared/api/queries'

const navItems: MenuProps['items'] = [
  { key: '/overview', icon: <DashboardOutlined />, label: <NavLink to="/overview">总览</NavLink> },
  { key: '/activity', icon: <GlobalOutlined />, label: <NavLink to="/activity">访问态势</NavLink> },
  { key: '/events', icon: <SearchOutlined />, label: <NavLink to="/events">事件检索</NavLink> },
  { key: '/ingest', icon: <DatabaseOutlined />, label: <NavLink to="/ingest">采集诊断</NavLink> },
  { key: '/risks', icon: <SafetyOutlined />, label: <NavLink to="/risks">风险 IP</NavLink> },
  { key: '/review', icon: <FileSearchOutlined />, label: <NavLink to="/review">人工复核</NavLink> },
  { key: '/shadow-runs', icon: <FieldTimeOutlined />, label: <NavLink to="/shadow-runs">影子运行</NavLink> },
  { key: '/audit', icon: <AuditOutlined />, label: <NavLink to="/audit">审计</NavLink> },
  {
    key: '/settings/rules',
    icon: <SettingOutlined />,
    label: <NavLink to="/settings/rules">规则</NavLink>,
  },
]

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const location = useLocation()
  const session = useSession()
  const selected = `/${location.pathname.split('/')[1] || 'overview'}`
  const selectedKey = location.pathname.startsWith('/settings') ? '/settings/rules' : selected

  const menu = (
    <Menu
      items={navItems}
      mode="inline"
      selectedKeys={[selectedKey]}
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
        trigger={null}
        width={232}
      >
        <div className="brand">
          <div className="brand-mark">PS</div>
          {!collapsed && (
            <div>
              <Typography.Text strong>Proxy Sentinel</Typography.Text>
              <Typography.Text type="secondary">检测运营台</Typography.Text>
            </div>
          )}
        </div>
        {menu}
      </Layout.Sider>
      <Layout>
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
            <Tag color="processing">Mock API</Tag>
          </Space>
          <Space>
            <Typography.Text type="secondary">
              {session.data?.user.name ?? '加载会话'} · {session.data?.role ?? 'unknown'}
            </Typography.Text>
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
        title="Proxy Sentinel"
      >
        {menu}
      </Drawer>
    </Layout>
  )
}
