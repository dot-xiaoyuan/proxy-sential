import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons'
import { Alert, Button, Form, Input, Typography } from 'antd'

import { useLogin } from '../shared/api/queries'

export function LoginPage() {
  const login = useLogin()
  return (
    <main className="login-page">
      <section className="login-card">
        <div className="login-brand"><SafetyCertificateOutlined /><div><Typography.Title level={3}>Proxy Sentinel</Typography.Title><Typography.Text type="secondary">高校网络风险运营平台</Typography.Text></div></div>
        {login.isError && <Alert className="margin-bottom-md" showIcon title="登录失败，请检查账号或稍后重试" type="error" />}
        <Form layout="vertical" onFinish={(values:{username:string;password:string})=>login.mutate(values)}>
          <Form.Item label="账号" name="username" rules={[{required:true,message:'请输入账号'}]}><Input autoComplete="username" prefix={<UserOutlined />} /></Form.Item>
          <Form.Item label="密码" name="password" rules={[{required:true,message:'请输入密码'}]}><Input.Password autoComplete="current-password" prefix={<LockOutlined />} /></Form.Item>
          <Button block htmlType="submit" loading={login.isPending} type="primary">登录运营平台</Button>
        </Form>
      </section>
    </main>
  )
}
