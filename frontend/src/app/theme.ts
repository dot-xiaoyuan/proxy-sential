import type { ThemeConfig } from 'antd'

export const proxySentinelTheme: ThemeConfig = {
  cssVar: { key: 'proxy-sentinel', prefix: 'ps' },
  token: {
    borderRadius: 8,
    borderRadiusSM: 6,
    colorBgContainer: '#ffffff',
    colorBgLayout: '#f8fafc',
    colorBorder: '#e2e8f0',
    colorBorderSecondary: '#edf2f7',
    colorLink: '#2257a7',
    colorLinkHover: '#1b4688',
    colorPrimary: '#2257a7',
    colorPrimaryHover: '#1b4688',
    colorText: '#0f172a',
    colorTextSecondary: '#475569',
    colorTextTertiary: '#64748b',
    controlHeight: 32,
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: 14,
  },
  components: {
    Button: { borderRadius: 6, defaultBorderColor: '#cbd5e1', primaryShadow: 'none' },
    Card: { borderRadiusLG: 8, headerFontSize: 15 },
    Input: { borderRadius: 6 },
    Segmented: {
      borderRadius: 6,
      itemSelectedBg: '#ffffff',
      itemSelectedColor: '#1b4688',
      trackBg: '#edf2f7',
    },
    Select: { borderRadius: 6 },
    Table: {
      cellPaddingBlock: 10,
      cellPaddingInline: 12,
      headerBg: '#f8fafc',
      headerColor: '#334155',
      rowHoverBg: '#f8fafc',
    },
    Tabs: { inkBarColor: '#2257a7', itemActiveColor: '#1b4688', itemSelectedColor: '#1b4688' },
    Tag: { borderRadiusSM: 4, defaultBg: '#f1f5f9', defaultColor: '#334155' },
  },
}
