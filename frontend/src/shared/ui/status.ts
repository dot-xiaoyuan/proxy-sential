// Unmapped execution states remain visible verbatim for troubleshooting.
export const statusLabels: Record<string,string> = {
 normal:'正常', suspicious:'可疑', high:'高风险', confirmed:'极高风险',
 confirmed_proxy:'确认代理', false_positive:'误报', benign:'良性', needs_more_data:'需补数据', unreviewed:'未复核',
 shadow:'影子模式', active:'真实模式', observe:'仅观测', manual:'人工确认', automatic:'自动执行',
 pending:'等待执行', queued:'等待执行', running:'执行中', succeeded:'成功', failed:'失败', blocked:'已阻断',
 complete:'已完成', completed:'已完成', partial:'部分完成', cancelled:'已停止', revoked:'已撤销',
 awaiting_approval:'等待审批', approved:'已批准', cooldown:'冷却中', observing:'观测中', recovered:'已恢复',
 disabled:'已停用', enabled:'已启用', ready:'就绪', degraded:'存在异常', healthy:'正常',
 ok:'正常', unavailable:'不可用', stale:'已过期', not_configured:'未配置', no_dhcp_events:'无 DHCP 事件', log_truncated:'日志轮转',
 new:'新建', assigned:'已分派', investigating:'调查中', waiting_data:'等待数据', resolved:'已解决', closed:'已关闭', reopened:'重新打开',
 error:'错误', warning:'警告', info:'提示', success:'成功', skipped:'已跳过',
 disconnect:'强制下线', rate_limit:'带宽降速', disable_account:'用户封禁', notify:'消息提醒', record:'仅记录',
}
export function statusText(value?: string | null) { return value ? statusLabels[value] ?? value : '' }
export function displayField(value?: string | null) {
 if(!value || /^(?:unknown|未知.*|未识别.*|未获取.*|未关联.*|待关联.*|未观测.*|[—-])$/i.test(value.trim()))return ''
 return value
}
