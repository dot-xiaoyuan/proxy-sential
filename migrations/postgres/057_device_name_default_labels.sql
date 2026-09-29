-- Exact default/model labels are not personalized names. Do not infer a model or
-- brand from an unauthenticated hostname. Raw events and manual notes are retained.
DELETE FROM device_name_evidence
WHERE source IN ('dhcp_hostname','dhcp_fqdn','mdns_hostname','mdns_service')
AND lower(split_part(value,'.',1)) IN ('localhost','localhost6','unknown','android','iphone','ipad','ady-al00','icl-al10','honor-100');
