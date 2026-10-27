import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons'
import { Button, Form, Input, Typography } from 'antd'
import { useState } from 'react'

import { ApiError } from '../shared/api/client'
import { useLogin } from '../shared/api/queries'
import { AppErrorAlert } from '../shared/ui'

function loginErrorMessage(error: unknown) {
  if (!(error instanceof ApiError)) return '无法连接登录服务，请检查网络后重试。'
  const detail = (() => {
    try {
      const parsed = JSON.parse(error.message) as { code?: string; message?: string }
      return `${parsed.code || ''} ${parsed.message || ''}`.toLowerCase()
    } catch {
      return error.message.toLowerCase()
    }
  })()
  if (error.status === 429 || detail.includes('too many login attempts')) return '登录尝试次数过多，请稍后再试。'
  if (error.status === 401) return '账号或密码不正确，请重新输入。'
  if (error.status === 409) return '当前环境不支持本地账号登录。'
  if (error.status === 400) return '账号和密码不能为空。'
  if (error.status >= 500) return '登录服务暂时不可用，请稍后重试。'
  return '登录失败，请稍后重试。'
}

export function LoginPage() {
  const login = useLogin()
  const [capsLock, setCapsLock] = useState(false)

  return (
    <main className="login-page">
      <div className="login-layout">
        <header className="login-topbar">
          <span className="login-mark" aria-hidden="true"><SafetyCertificateOutlined /></span>
          <div className="login-brand-copy">
            <strong>Proxy Sentinel</strong>
            <span>高校网络风险运营平台</span>
          </div>
        </header>

        <div className="login-main">
          <section className="login-card" aria-labelledby="login-card-title">
            <div className="login-card-heading">
              <Typography.Title level={1} id="login-card-title">登录</Typography.Title>
            </div>

            {login.isError && <AppErrorAlert className="margin-bottom-md" title="登录失败" message={loginErrorMessage(login.error)} />}
            <Form
              className="login-form"
              layout="vertical"
              onFinish={(values: { username: string; password: string }) => login.mutate(values)}
              onValuesChange={() => { if (login.isError) login.reset() }}
            >
              <Form.Item label="账号" name="username" rules={[{ required: true, message: '请输入账号' }]}>
                <Input autoFocus autoComplete="username" placeholder="请输入账号" prefix={<UserOutlined />} />
              </Form.Item>
              <Form.Item
                label="密码"
                name="password"
                rules={[{ required: true, message: '请输入密码' }]}
                extra={capsLock ? <span className="login-caps-hint">大写锁定已开启</span> : undefined}
              >
                <Input.Password
                  autoComplete="current-password"
                  placeholder="请输入密码"
                  prefix={<LockOutlined />}
                  onKeyDown={event => setCapsLock(event.getModifierState('CapsLock'))}
                  onKeyUp={event => setCapsLock(event.getModifierState('CapsLock'))}
                  onBlur={() => setCapsLock(false)}
                />
              </Form.Item>
              <Button block htmlType="submit" loading={login.isPending} type="primary">登 录</Button>
            </Form>

          </section>
        </div>

      </div>
    </main>
  )
}
