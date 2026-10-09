import type { ThemeConfig } from 'antd'

export const proxySentinelTheme: ThemeConfig = {
  cssVar: { key: 'proxy-sentinel', prefix: 'ps' },
  token: {
    borderRadius: 8,
    colorBgLayout: '#f8fafc',
    colorBorder: '#e2e8f0',
    colorPrimary: '#2257a7',
    colorText: '#0f172a',
    colorTextSecondary: '#475569',
    controlHeight: 32,
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: 14,
  },
  components: {
    Card: { borderRadiusLG: 8 },
    Table: { cellPaddingBlock: 10, cellPaddingInline: 12 },
    Tag: { defaultBg: '#f1f5f9', defaultColor: '#475569' },
  },
}
