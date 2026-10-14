-- 南昌大学前湖校区基础位置资料；仅补充缺项，不覆盖现场配置。
-- 来源：https://iec.ncu.edu.cn/info/1551/14706.htm（2025-06-20，核实于 2026-10-13）
-- 慧源 1–4 栋、修贤 5–18 栋、天健 19–30 栋；其余楼宇来自该页校园地标及环游车站点。
-- 社区是位置目录，不代表已核实的网络边界；不推定 CIDR、SSID、VLAN 或 AP/NAS。
DO $$
DECLARE
  target_campus text;
  building_number integer;
  community text;
  location record;
BEGIN
  SELECT campus_id INTO target_campus FROM campuses
  WHERE campus_id = 'ncu' OR code = 'NCU-QH'
     OR name IN ('前湖校区', '南昌大学前湖校区', '南昌大学（前湖校区）')
  ORDER BY CASE WHEN campus_id = 'ncu' THEN 0 ELSE 1 END, campus_id LIMIT 1;
  IF target_campus IS NULL THEN
    target_campus := 'ncu';
    INSERT INTO campuses(campus_id, code, name, attributes)
    VALUES(target_campus, 'NCU-QH', '南昌大学（前湖校区）',
      '{"address":"江西省南昌市红谷滩区学府大道999号","source_url":"https://iec.ncu.edu.cn/info/1551/14706.htm"}');
  END IF;
  FOR building_number IN 1..30 LOOP
    community := CASE WHEN building_number <= 4 THEN '慧源' WHEN building_number <= 18 THEN '修贤' ELSE '天健' END;
    INSERT INTO buildings(building_id,campus_id,code,name,attributes)
    SELECT 'ncu-qh-dorm-' || building_number, target_campus, 'QH-DORM-' || building_number,
           community || building_number || '栋', '{"source_url":"https://iec.ncu.edu.cn/info/1551/14706.htm"}'::jsonb
    WHERE NOT EXISTS (SELECT 1 FROM buildings WHERE campus_id=target_campus AND name=community || building_number || '栋')
    ON CONFLICT DO NOTHING;
  END LOOP;
  FOR location IN SELECT * FROM (VALUES
    ('library','图书馆'),('administration','行政楼'),('gymnasium','体育馆'),
    ('swimming','游泳馆'),('basic-lab','基础实验大楼'),('science','理生楼'),
    ('materials','材料楼'),('information','信工楼'),('mechanical','机电楼'),
    ('construction','建工楼'),('hospital','校医院')) AS locations(code,name)
  LOOP
    INSERT INTO buildings(building_id,campus_id,code,name,attributes)
    SELECT 'ncu-qh-' || location.code,target_campus,'QH-' || upper(location.code),location.name,
           '{"source_url":"https://iec.ncu.edu.cn/info/1551/14706.htm"}'::jsonb
    WHERE NOT EXISTS (SELECT 1 FROM buildings WHERE campus_id=target_campus AND name=location.name)
    ON CONFLICT DO NOTHING;
  END LOOP;
  FOR location IN SELECT * FROM (VALUES ('huiyuan','慧源社区'),('xiuxian','修贤社区'),('tianjian','天健社区'),('kangjian','康健社区')) AS locations(code,name)
  LOOP
    INSERT INTO network_zones(network_zone_id,campus_id,name)
    SELECT 'ncu-qh-' || location.code,target_campus,location.name
    WHERE NOT EXISTS (SELECT 1 FROM network_zones WHERE campus_id=target_campus AND name=location.name)
    ON CONFLICT DO NOTHING;
  END LOOP;
END $$;
