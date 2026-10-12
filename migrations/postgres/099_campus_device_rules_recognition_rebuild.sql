-- Device rules now read the DHCP vendor class and recognise campus routers,
-- access points, switches, printers and IoT terminals. Recognition jobs only
-- run when an endpoint changes and are claimed oldest first, so re-enqueueing
-- every recent endpoint would queue new arrivals behind a rebuild lasting hours
-- (about 1.4 jobs/s on 184). Re-enqueue only recent endpoints whose
-- self-reported DHCP fields can match a new rule; everything else picks the new
-- rules up on its next DHCP renewal.
INSERT INTO endpoint_recognition_jobs(endpoint_id)
SELECT endpoint_id FROM endpoint_entities
WHERE entity_role='endpoint' AND last_seen>now()-interval '7 days'
AND (coalesce(attributes->>'vendor_class','') ~* '^(HP |huawei AP|H3C|TL-|HUAWEI:openharmony:|Alpha Egg|YouDao|udhcp |dhcpcd-[0-9.]+:Linux-[^:]+:(armv|aarch64|mips|riscv)|Linux [0-9][0-9.]* (mips|armv))'
  OR coalesce(attributes->>'hostname','') ~* '(TL[- _]?(WDR|XDR|WR|WTR|ER|MR|SG|SF|SL|SH|X?AP)[0-9]|MiWiFi|Huawei AP-|^(NPI|HP)[0-9A-F]{6}$|chuangmi\.camera|IPCamera|^MITV|midea_|uplus-haier-|YoudaoDictionaryPen|Alpha ?Egg|iFlytek-AiNote|espressif|^ESP[_-]|seewo-PC|rong-yao|lian-xiang|xiao-xin|zheng-jiu-zhe|^yi-jia)')
ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=now();
