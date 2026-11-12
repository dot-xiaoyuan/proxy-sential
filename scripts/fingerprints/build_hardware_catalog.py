#!/usr/bin/env python3
"""Build V8 hardware rules from pinned raw sources; never execute upstream code.

Run with PyYAML 6.0.3. Unsupported syntax is retained with its source location;
an unsupported AND operand invalidates the whole branch, never broadens it.
The legacy V7 converter and runtime remain unchanged.
"""
import argparse, hashlib, json, re
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
VERSION = 'hardware-catalog-2026-11-12.2'
CONVERTER = 'sentinel-hardware-converter/1'
RECOG_FIELDS = {'snmp_sysdescr':'snmp_sysdescr','http_servers':'http_server','html_title':'http_title','http_wwwauth':'http_www_authenticate','mdns_device-info_txt':'mdns_model','ssh_banners':'ssh_banner','sip_banners':'sip_server','x509_subjects':'tls_subject','x509_issuers':'tls_issuer','dhcp_vendor_class':'dhcp_vendor_class','sip_user_agents':'sip_user_agent'}

class Unsupported(ValueError): pass

def regex(value):
    if not isinstance(value,str) or len(value)<2 or value[0] not in '/#~': raise Unsupported('unsupported regex delimiter')
    end=value.rfind(value[0]); flags=value[end+1:]
    if end==0 or any(f not in 'ims' for f in flags): raise Unsupported('unsupported regex flags')
    return ('(?'+flags+')' if flags else '') + value[1:end]

def atom(field, operator, value):
    if not isinstance(value,str) or not value: raise Unsupported('empty/non-string condition')
    if operator=='regex': value=regex(value)
    if operator=='oid_prefix':
        value=value.strip('.')
        if not re.fullmatch(r'\d+(?:\.\d+)+',value): raise Unsupported('invalid numeric OID')
    return dict(field=field,operator=operator,value=value)

def condition(branch):
    if not isinstance(branch,dict) or not branch: raise Unsupported('empty discovery branch')
    out=[]
    for key,value in branch.items():
        negative=key.endswith('_except'); key=key.removesuffix('_except')
        if key=='snmpget':
            # LibreNMS snmpget is one predicate or a list of OR predicates.
            values=value if isinstance(value,list) else [value]; nodes=[]
            for v in values:
                if not isinstance(v,dict) or set(v)-{'oid','op','value'}: raise Unsupported('unsupported snmpget parameters')
                oid=str(v.get('oid','')).strip('.')
                if not re.fullmatch(r'\d+(?:\.\d+)+',oid): raise Unsupported('snmpget symbolic OID needs explicit resolution')
                op={'=':'exact','==':'exact','contains':'contains','regex':'regex','!=':'not_exact'}.get(v.get('op','='))
                if not op: raise Unsupported('unsupported snmpget operator')
                node=atom('oid:'+oid,'exact' if op=='not_exact' else op,v.get('value'))
                if op=='not_exact':node={'not':node}
                nodes.append(node)
        else:
            fields={'sysObjectID':('snmp_sysoid','oid_prefix'),'sysObjectID_regex':('snmp_sysoid','regex'),'sysDescr':('snmp_sysdescr','contains'),'sysDescr_regex':('snmp_sysdescr','regex')}
            if key not in fields: raise Unsupported('unsupported condition '+key)
            values=value if isinstance(value,list) else [value]
            nodes=[atom(*fields[key],v) for v in values]
        if not nodes: raise Unsupported('empty condition list')
        node=nodes[0] if len(nodes)==1 else {'any':nodes}
        out.append({'not':node} if negative else node)
    return out[0] if len(out)==1 else {'all':out}

def hardware_type(d):
    # `network` is an OS grouping, not evidence that the chassis is a switch.
    if d.get('type')=='environment':return 'environment_monitor'
    if d.get('type')=='power':
        name=d.get('text','').lower()
        if re.search(r'\bpdu\b|power distribution',name):return 'pdu'
        if re.search(r'\bups\b|uninterruptible',name):return 'ups'
    return ''

def extraction(raw, name):
    path='librenms/resources/definitions/os_discovery/'+name+'.yaml'
    if path not in raw:return [],'pinned os_discovery source unavailable'
    d=yaml.load(raw[path],Loader=yaml.BaseLoader).get('modules',{}).get('os',{})
    if not d:return [],'os_discovery has no declarative hardware extraction'
    unsupported=set(d)&{'hardware_template','hardware_replace','hardware_mib'}
    if unsupported:return [],'unsupported hardware transformation: '+','.join(sorted(unsupported))
    out=[]
    for value in d.get('sysDescr_regex',[]) if isinstance(d.get('sysDescr_regex'),list) else [d.get('sysDescr_regex')]:
        if value and '(?<hardware>' in value:
            out.append(dict(field='snmp_sysdescr',pattern=regex(value),capture='hardware',raw_ref=path,raw_sha256=hashlib.sha256(raw[path].encode()).hexdigest()))
    values=d.get('hardware',[]);values=values if isinstance(values,list) else [values]
    resolved={'VERTIV-V5-MIB::productModelNumber.0':'1.3.6.1.4.1.21239.5.2.1.8.0'}
    for value in values:
        oid=resolved.get(value,value).strip('.')
        if not re.fullmatch(r'\d+(?:\.\d+)+',oid):return [],'unresolved hardware OID '+value
        item=dict(field='oid:'+oid,raw_ref=path,raw_sha256=hashlib.sha256(raw[path].encode()).hexdigest())
        if d.get('hardware_regex'):item.update(pattern=regex(d['hardware_regex']),capture='hardware')
        if value in resolved:
            item['resolution_ref']='librenms/mibs/vertiv/VERTIV-V5-MIB'
            item['resolution_sha256']=hashlib.sha256(raw[item['resolution_ref']].encode()).hexdigest()
        out.append(item)
    return out,'' if out else 'hardware extraction unavailable'

def model_provenance(rule,raw,path,positive,rationale):
    rule.update(raw_ref=path,raw_sha256=hashlib.sha256(raw[path].encode()).hexdigest(),rationale=rationale,positive=positive,negative=['Hikvision','Generic device','not-'+positive[0]+'-other'])
    # Unanchored legacy family rules intentionally match embedded model tokens;
    # a negative with that token would be an invalid fixture.
    if not rule['pattern'].startswith('(?i)^'):rule['negative']=rule['negative'][:2]
    return rule

def build(raw,legacy,models,products):
    sources=[dict(name=s['id'],version=s['version'],url=s['url'],license=s['license']) for s in legacy['sources'] if s['id'] in {'recog','librenms','openwrt'}]
    result=dict(version=VERSION,converter_version=CONVERTER,sources=sources,recog_files={},models=[],snmp=[],unsupported=[])
    for name,value in sorted(raw.items()):
        if name.startswith('recog/xml/') and name.endswith('.xml'):
            result['recog_files'][name]=RECOG_FIELDS.get(Path(name).stem,'')
        if not name.startswith('librenms/resources/definitions/os_detection/') or not name.endswith('.yaml'):continue
        d=yaml.load(value,Loader=yaml.BaseLoader)
        for i,b in enumerate(d.get('discovery',[])):
            rule=dict(id=name+':'+str(i),source='librenms',version=next(s['version'] for s in sources if s['name']=='librenms'),name=d.get('text',''),type=hardware_type(d),raw_ref=name,raw_sha256=hashlib.sha256(value.encode()).hexdigest())
            try:rule['condition']=condition(b)
            except Unsupported as e:
                result['unsupported'].append(dict(source='librenms',rule_id=rule['id'],reason=str(e)));continue
            extract,reason=extraction(raw,Path(name).stem)
            if extract:rule['extractors']=extract
            elif reason:result['unsupported'].append(dict(source='librenms_hardware',rule_id=name,reason=reason))
            result['snmp'].append(rule)
    # Only explicitly reviewed model-code entries become hardware rules.
    for code,d in sorted(models['entries'].items()):
        rule=dict(id='model-catalog:'+code,source='verified_model',version=models['version'],pattern='(?i)^'+re.escape(code)+'$',type=d.get('device_type',''),model=d.get('model',''),manufacturer=d.get('brand',''))
        result['models'].append(model_provenance(rule,raw,'verified/model-catalog.json',[code],'Existing reviewed vendor model-code entry; only device self-report fields accepted'))
    examples=['DS-7908N-R4(C)','DS-8832N-R8(C)','DS-7916N-K4','iDS-2DC3A40BX-DE','DS-2CD1345V2-LA','DS-7616NI-K2','DS-K1T6QT-F72M','DH-IPC-HFW1230S','DH-NVR4104','AppleTV6,2','Chromecast Ultra','ZKTeco UA100']
    for i,d in enumerate(products['entries']):
        rule=dict(id='product-rules:'+str(i),source='verified_product',version=products['version'],pattern=d['pattern'],type=d['product_kind'],manufacturer=d.get('manufacturer',''))
        result['models'].append(model_provenance(rule,raw,'verified/product-rules.json',[examples[i]],'Reviewed product-family hardware mapping; attendance use is not inferred'))
    toh=json.loads(raw['openwrt/toh.json']);reviewed={'RT-AC68U','WRT1900ACS','Archer C7','TL-WR841N'};seen=set()
    for row in toh['entries']:
        d=dict(zip(toh['columns'],row));model=d.get('model')
        if model not in reviewed or model in seen or d.get('devicetype')!='WiFi Router':continue
        seen.add(model)
        rule=dict(id='openwrt:'+d['deviceid'],source='openwrt',version=next(s['version'] for s in sources if s['name']=='openwrt'),pattern='(?i)^(?:'+re.escape(d['brand'])+' )?'+re.escape(model)+'$',type='router',model=model,manufacturer=d['brand'],source_url='https://openwrt.org/'+d['devicepage'].replace(':','/'))
        result['models'].append(model_provenance(rule,raw,'openwrt/toh.json',[model,d['brand']+' '+model],'Reviewed exact product with explicit WiFi Router role in pinned OpenWrt table; does not imply network violation'))
    result['unsupported'].append(dict(source='openwrt',rule_id='dictionary',reason='Only four exact model families reviewed; all other dictionary entries remain clues'))
    # Hardware extraction is a separate stage; count each OS definition once.
    hardware_gaps={u['rule_id']:u for u in result['unsupported'] if u['source']=='librenms_hardware'}
    result['unsupported']=[u for u in result['unsupported'] if u['source']!='librenms_hardware']+list(hardware_gaps.values())
    executable_hardware=len({r['raw_ref'] for r in result['snmp'] if r.get('extractors')})
    result['source_counts']={'openwrt':len(toh['entries']),'librenms_hardware':len(hardware_gaps)+executable_hardware}
    reviewed=json.loads(raw['verified/reviewed-hardware-models.json'])
    for entry in reviewed['entries']:
        rule=dict(entry,source='verified_model',version=reviewed['version'],raw_ref='verified/reviewed-hardware-models.json',raw_sha256=hashlib.sha256(raw['verified/reviewed-hardware-models.json'].encode()).hexdigest())
        result['models'].append(rule)
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    data=ROOT/'internal/fingerprint/data'
    raw=json.loads((data/'multisource-provenance.json').read_text());raw.update(json.loads((data/'hardware-provenance.json').read_text()))
    raw['verified/reviewed-hardware-models.json']=(data/'reviewed-hardware-models.json').read_text()
    result=build(raw,json.loads((data/'multisource-catalog.json').read_text()),json.loads(raw['verified/model-catalog.json']),json.loads(raw['verified/product-rules.json']))
    a.output.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(models=len(result['models']),snmp=len(result['snmp']),recog_files=len(result['recog_files']),unsupported=len(result['unsupported']))))

if __name__=='__main__':main()
