import { useState } from 'react'
import { UploadOutlined } from '@ant-design/icons'
import { App as AntApp, Alert, Button, Descriptions, Skeleton, Space, Tag, Typography, Upload } from 'antd'

import { useDeviceFingerprintLibrary, useImportDeviceFingerprintBundle, useReloadRules, useSession, useValidateDeviceFingerprintBundle } from '../shared/api/queries'
import type { DeviceFingerprintBundleManifest } from '../shared/api/types'
import { can } from '../shared/auth/permissions'

const shadowActions = ['record', 'shadow_watch', 'shadow_manual_review', 'shadow_confirm_review']

export function RulesPage() {
  const session = useSession()
  const { message } = AntApp.useApp()
  const reloadRules = useReloadRules()
  const fingerprintLibrary = useDeviceFingerprintLibrary()
  const validateBundle = useValidateDeviceFingerprintBundle()
  const importBundle = useImportDeviceFingerprintBundle()
  const [bundleFile,setBundleFile] = useState<File|null>(null)
  const [manifest,setManifest] = useState<DeviceFingerprintBundleManifest|null>(null)
  const allowed = can(session.data, 'rules:reload')
  const canUpdateLibrary = can(session.data, 'device-fingerprint-library:update')

  if (session.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            规则配置
          </Typography.Title>
          <Typography.Text type="secondary">第一阶段只保留影子 reload 入口，不触发处罚动作。</Typography.Text>
        </div>
      </div>
      {!allowed && <Alert showIcon className="margin-bottom-md" title="当前会话没有 rules:reload 权限" type="warning" />}
      <section className="surface">
        <Typography.Title level={4}>影子模式规则矩阵</Typography.Title>
        <Descriptions bordered column={1} size="small" className="margin-bottom-lg">
          <Descriptions.Item label="配置版本">
            <Typography.Text className="mono">mock-rules-20260727</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="运行模式">
            <Tag color="processing">shadow</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="动作边界">
            <Space wrap size={[6, 6]}>
              {shadowActions.map((action) => (
                <Tag color="blue" key={action} className="tag-margin-zero">
                  {action}
                </Tag>
              ))}
            </Space>
          </Descriptions.Item>
        </Descriptions>
        <Space wrap>
          <Button
            disabled={!allowed}
            loading={reloadRules.isPending}
            onClick={() =>
              reloadRules.mutate(undefined, {
                onSuccess: (result) => message.success(`规则 reload ${result.status}`),
              })
            }
            type="default"
          >
            影子 reload 重新加载
          </Button>
          <Typography.Text type="secondary" className="font-size-sm">
            此操作仅热重载风控规则与权重系数，不会写回防火墙或阻塞流量。
          </Typography.Text>
        </Space>
      </section>
      <section className="surface">
        <Typography.Title level={4}>设备特征库</Typography.Title>
        {fingerprintLibrary.isError ? <Alert showIcon type="error" title="设备特征库状态加载失败" /> : <Descriptions bordered column={1} size="small" className="margin-bottom-lg" items={[
          {key:'version',label:'当前版本',children:<Typography.Text className="mono list-cell-nowrap">{fingerprintLibrary.data?.version || '-'}</Typography.Text>},
          {key:'source',label:'数据来源',children:fingerprintLibrary.data?.source || '-'},
          {key:'status',label:'运行状态',children:<Tag color={fingerprintLibrary.data?.status === 'ready' ? 'green' : 'gold'}>{fingerprintLibrary.data?.status || 'loading'}</Tag>},
          {key:'updated',label:'最近更新',children:fingerprintLibrary.data?.updated_at ? new Date(fingerprintLibrary.data.updated_at).toLocaleString() : '内置离线版本'},
          {key:'error',label:'最近错误',children:fingerprintLibrary.data?.last_error || '无'},
          {key:'mode',label:'更新模式',children:fingerprintLibrary.data?.offline_mode ? '离线包导入（30 机器不访问外网）' : '联网更新'},
          {key:'counts',label:'规则规模',children:`OUI ${fingerprintLibrary.data?.oui_count ?? 0} · UA/自有规则 ${fingerprintLibrary.data?.rule_count ?? 0} · DHCP ${fingerprintLibrary.data?.dhcp_rule_count ?? 0} · 域名 ${fingerprintLibrary.data?.domain_rule_count ?? 0} / ${fingerprintLibrary.data?.domain_ecosystem_count ?? 0} 个生态`},
		  {key:'domain-source',label:'域名规则版本',children:<Typography.Text className="mono list-cell-nowrap">{fingerprintLibrary.data?.domain_source_version || 'v1 包未包含域名规则'}</Typography.Text>},
		  {key:'domain-backfill',label:'域名证据回填',children:`${fingerprintLibrary.data?.domain_backfill_status || '未启动'} · ${fingerprintLibrary.data?.domain_backfill_processed ?? 0} 条`},
		  {key:'domain-error',label:'域名回填错误',children:fingerprintLibrary.data?.domain_backfill_last_error || '无'},
          {key:'backfill',label:'画像回填',children:`${fingerprintLibrary.data?.backfill_status || '未启动'} · ${fingerprintLibrary.data?.backfill_processed ?? 0} 条`},
          {key:'licenses',label:'数据许可',children:(fingerprintLibrary.data?.licenses || ['IEEE public registry','Apache-2.0']).join('、')},
        ]} />}
        <div className="fingerprint-import-panel">
          <Space wrap>
            <Upload accept=".gz,.tgz,application/gzip" beforeUpload={(file)=>{setBundleFile(file);setManifest(null);validateBundle.mutate(file,{onSuccess:setManifest,onError:(error)=>message.error(error.message)});return false}} fileList={bundleFile ? [{uid:bundleFile.name,name:bundleFile.name,status:manifest?'done':'uploading'}] : []} maxCount={1} onRemove={()=>{setBundleFile(null);setManifest(null)}} showUploadList>
              <Button disabled={!canUpdateLibrary} icon={<UploadOutlined />} loading={validateBundle.isPending}>选择并校验离线包</Button>
            </Upload>
            <Button type="primary" disabled={!canUpdateLibrary || !bundleFile || !manifest} loading={importBundle.isPending} onClick={()=>bundleFile && importBundle.mutate(bundleFile,{onSuccess:(result)=>{message.success(`特征库已导入 ${result.version}`);setBundleFile(null);setManifest(null)},onError:(error)=>message.error(error.message)})}>确认导入</Button>
          </Space>
          {manifest && <Alert showIcon type="success" title={`校验通过：${manifest.version}`} description={`生成时间 ${new Date(manifest.created_at).toLocaleString()} · ${manifest.sources.map(source=>`${source.name} ${source.version}`).join(' · ')}`} />}
          <Typography.Text type="secondary">离线包在可联网开发机生成；30 机器只执行校验、原子切换和画像回填，不上传现场设备数据。</Typography.Text>
        </div>
      </section>
    </main>
  )
}
