const correctionReasons: Record<string, string> = {
  saved_evidence_unavailable: '原决策缺少可核验的证据内容',
  saved_decision_unreadable_or_mismatched: '原决策内容无法核验',
  strong_anchor_missing: '原证据缺少强锚点',
  device_lower_bound_below_two: '原证据的设备数量下界不足两台',
  coverage_or_conflict_not_verified: '原证据的采集覆盖或冲突未通过核验',
}

export function evidenceReviewReason(reason?: string) {
  return reason ? correctionReasons[reason] ?? reason : ''
}
