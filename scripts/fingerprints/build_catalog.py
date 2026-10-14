#!/usr/bin/env python3
"""Build an auditable catalog from pinned local upstream snapshots (no code execution).
Requires PyYAML==6.0.3. Use --snapshots for the checkout directory. The Go
finalizer validates RE2 and example compatibility before writing embedded data.
"""
import argparse, base64, hashlib, json, re, subprocess, xml.etree.ElementTree as ET
from pathlib import Path
import yaml

CONVERTER = "sentinel-source-converter/1"
ROLE = {
    "Smart TV": "tv",
    "SmartTV": "tv",
    "IPTV": "tv",
    "Ethernet Adapter": "network_adapter",
    "Serial to Ethernet": "network_adapter",
    "Sensor": "iot",
    "Light Bulb": "iot",
    "Building Automation": "iot",
    "Home Assistant": "iot",
    "SmartWatch": "wearable",
    "Smart Switch": "iot",
    "Media Player": "media_device",
    "Multimedia Device": "media_device",
    "Digital Media Receiver": "media_device",
    "Digital Media Player": "media_device",
    "Multifunction Device": "printer",
    "Print Server": "print_server",
    "Scanner": "scanner",
    "Web Cam": "camera",
    "Wireless Controller": "wireless_controller",
    "Thin Client": "desktop",
    "Workstation": "desktop",
    "UPS": "ups",
    "Storage": "storage",
    "File Storage": "storage",
    "Router": "router",
    "Broadband Router": "router",
    "Wireless Router": "router",
    "WAP": "access_point",
    "Wireless Access Point": "access_point",
    "Switch": "switch",
    "Printer": "printer",
    "IP Camera": "camera",
    "IP Network Camera": "camera",
    "DVR": "nvr",
    "VoIP": "voip_phone",
    "VoIP Phone": "voip_phone",
    "SIP Gateway": "voip_phone",
    "Mobile Phone": "mobile",
    "Smartphone": "mobile",
    "Tablet": "tablet",
    "Desktop": "desktop",
    "Laptop": "laptop",
    "NAS": "nas",
    "Media Server": "media_device",
    "Game Console": "media_device",
    "Digital Signage": "display",
    "Firewall": "firewall",
    "Power Device": "ups",
}
FIELDS = {
    "http_header.server": "http_server",
    "html.title": "http_title",
    "tls.subject": "tls_subject",
    "tls.issuer": "tls_issuer",
    "x509.subject": "tls_subject",
    "x509.issuer": "tls_issuer",
    "dhcp.vendor_class": "dhcp_vendor_class",
    "mdns.device-info.txt": "mdns_model",
    "snmp.sysdescr": "snmp_sysdescr",
    "ssh.banner": "ssh_banner",
    "sip.banner": "sip_server",
    "sip.useragent": "sip_user_agent",
    "http_header.www-authenticate": "http_www_authenticate",
    "favicon.md5": "favicon_md5",
}
FILES = {
    "http_servers": "http_server",
    "html_title": "http_title",
    "x509_subjects": "tls_subject",
    "x509_issuers": "tls_issuer",
    "dhcp_vendor_class": "dhcp_vendor_class",
    "mdns_device-info_txt": "mdns_model",
    "snmp_sysdescr": "snmp_sysdescr",
    "ssh_banners": "ssh_banner",
    "sip_banners": "sip_server",
    "sip_user_agents": "sip_user_agent",
    "http_wwwauth": "http_www_authenticate",
    "favicons": "favicon_md5",
}


class Builder:
    def __init__(self, root):
        self.root = root
        self.sources = []
        self.rules = []
        self.provenance = {}

    def source(self, id, name, url, license, path=None, status="registered", reason=""):
        version = (
            json.loads((self.root / "versions.json").read_text()).get(id, "")
            if (self.root / "versions.json").exists()
            else ""
        )
        checksum = ""
        if path:
            path = Path(path)
            if (path / ".git").exists():
                version = subprocess.check_output(
                    ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
                ).strip()
        self.sources.append(
            dict(
                id=id,
                name=name,
                url=url,
                license=license,
                version=version,
                checksum=checksum,
                converter_version=CONVERTER,
                status=status,
                reason=reason,
            )
        )
        return self.sources[-1]

    def raw(self, source, path):
        data = path.read_bytes()
        key = (
            source + "/" + path.relative_to(self.root / source).as_posix()
            if (self.root / source).is_dir()
            else source + "/" + path.name
        )
        self.provenance[key] = data.decode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def rule(self, source, original, name, conditions=None, **kw):
        s = next(s for s in self.sources if s["id"] == source)
        r = dict(
            id=source + ":" + hashlib.sha256(original.encode()).hexdigest()[:20],
            source_id=source,
            original_id=original,
            version=s["version"] or "snapshot",
            name=name,
            protocol="",
            direction="host",
            conditions=conditions or [],
            status="unsupported_input",
            reason="缺少对应标准事件字段",
            strength="auxiliary",
            examples=[],
        )
        r.update(kw)
        self.rules.append(r)
        return r

    def finish(self):
        for s in self.sources:
            vals = {
                k: v for k, v in self.provenance.items() if k.startswith(s["id"] + "/")
            }
            if vals:
                rules = [r for r in self.rules if r["source_id"] == s["id"]]

                def upstream_id(r):
                    parts = r["original_id"].split(":")
                    return (
                        ":".join(parts[:2])
                        if s["id"] == "satori"
                        else (
                            parts[0]
                            if s["id"] in ["librenms", "whatweb"]
                            else r["original_id"]
                        )
                    )

                s["upstream_count"] = len(set(upstream_id(r) for r in rules))
                material = "".join(
                    k + "\x00" + hashlib.sha256(v.encode()).hexdigest() + "\n"
                    for k, v in sorted(vals.items())
                )
                s["checksum"] = hashlib.sha256(material.encode()).hexdigest()
                s["license_files"] = [
                    k
                    for k in vals
                    if Path(k).name.lower() in ["license", "copying", "license.txt"]
                ]
                s["snapshot_url"] = (
                    (
                        "https://raw.githubusercontent.com/"
                        + {
                            "recog": "rapid7/recog",
                            "satori": "xnih/satori",
                            "librenms": "librenms/librenms",
                            "whatweb": "urbanadventurer/WhatWeb",
                            "p0f": "p0f/p0f",
                        }.get(s["id"], "")
                        + "/"
                        + s["version"]
                        + "/"
                    )
                    if s["id"] != "openwrt"
                    else "https://openwrt.org/toh.json"
                )
        return dict(version=CONVERTER, sources=self.sources, rules=self.rules)


def cond(field, value, op="regex"):
    return dict(field=field, operator=op, value=value)


def licenses(b, id, p):
    for f in p.glob("*"):
        if f.is_file() and any(
            x in f.name.lower() for x in ["license", "copying", "notice", "readme"]
        ):
            b.raw(id, f)


def recog(b):
    p = b.root / "recog"
    b.source(
        "recog", "Rapid7 Recog", "https://github.com/rapid7/recog", "BSD-2-Clause", p
    )
    licenses(b, "recog", p)
    for f in sorted((p / "xml").glob("*.xml")):
        b.raw("recog", f)
        root = ET.parse(f).getroot()
        field = FILES.get(f.stem, FIELDS.get(root.get("matches")))
        for i, fp in enumerate(root.findall("fingerprint")):
            params = {
                x.get("name"): x.get("value")
                or ("$" + x.get("pos", "0") if x.get("pos", "0") != "0" else "")
                for x in fp.findall("param")
            }
            pattern = fp.get("pattern", "")
            invalid_example = False
            flags = fp.get("flags", "").split(",")
            known_flags = {
                "REG_ICASE": "i",
                "REG_MULTILINE": "m",
                "REG_DOT_NEWLINE": "s",
            }
            pattern = (
                "(?" + "".join(known_flags[x] for x in flags if x in known_flags) + ")"
                if any(x in known_flags for x in flags)
                else ""
            ) + pattern
            cs = [cond(field or root.get("matches", f.stem), pattern)]
            examples = []
            for e in fp.findall("example"):
                value = e.text or ""
                if e.get("encoding") == "base64":
                    try:
                        value = base64.b64decode(value).decode()
                    except (ValueError, UnicodeError):
                        invalid_example = True
                        continue
                examples.append(dict(values={cs[0]["field"]: value}, match=True))
            b.rule(
                "recog",
                f.name + ":" + str(i),
                fp.findtext("description") or f.stem,
                cs,
                protocol=root.get("protocol", ""),
                direction="client" if field == "dhcp_vendor_class" else "server",
                brand=params.get("hw.vendor", ""),
                model=params.get("hw.product", ""),
                original_type=params.get("hw.device", ""),
                role=ROLE.get(params.get("hw.device", "").strip(), ""),
                os=params.get("os.family", ""),
                status=(
                    "invalid_data"
                    if invalid_example
                    else "converted" if field else "unsupported_input"
                ),
                reason=(
                    "上游样例编码无效"
                    if invalid_example
                    else "" if field else "协议字段尚未纳入标准设备事件"
                ),
                examples=examples,
                strength=(
                    "self_report"
                    if params.get("hw.device")
                    and field not in ["tls_subject", "tls_issuer", "favicon_md5"]
                    else "auxiliary"
                ),
            )


def satori(b):
    p = b.root / "satori"
    b.source("satori", "Satori", "https://github.com/xnih/satori", "GPL-2.0", p)
    licenses(b, "satori", p)
    for f in sorted((p / "fingerprints").glob("*.xml")):
        b.raw("satori", f)
        try:
            root = ET.parse(f).getroot()
        except ET.ParseError as e:
            b.rule("satori", f.name, f.name, status="invalid_data", reason=str(e))
            continue
        for i, fp in enumerate(root.findall(".//fingerprint")):
            tests = fp.findall(".//test")
            if not tests:
                b.rule(
                    "satori",
                    f"{f.name}:{i}",
                    fp.get("name", ""),
                    status="invalid_data",
                    reason="指纹没有匹配条件",
                )
            for j, t in enumerate(tests):
                a = t.attrib
                cs = []
                ok = f.stem in ["dhcp", "ssh", "sip", "web", "webuseragent"]
                mapping = {
                    "dhcpoption55": "dhcp_requested_options",
                    "dhcpvendorcode": "dhcp_vendor_class",
                    "ssh": "ssh_banner",
                    "sipserver": "sip_server",
                    "webserver": "http_server",
                    "webuseragent": "user_agent",
                }
                for k, v in a.items():
                    if k in ["weight", "matchtype", "dhcptype"]:
                        continue
                    field = mapping.get(k, k)
                    cs.append(
                        cond(
                            field,
                            v,
                            {
                                "exact": "exact",
                                "partial": "contains",
                                "regex": "regex",
                            }.get(a.get("matchtype"), "unsupported"),
                        )
                    )
                    ok = ok and k in mapping
                # A message-type constraint cannot be dropped without broadening a match.
                ok = (
                    ok
                    and a.get("dhcptype", "Any") == "Any"
                    and a.get("matchtype") in ["exact", "regex", "partial"]
                    and bool(cs)
                )
                b.rule(
                    "satori",
                    f"{f.name}:{i}:{j}",
                    fp.get("name", ""),
                    cs,
                    protocol=f.stem,
                    direction=(
                        "server"
                        if f.stem in ["web", "sip"]
                        else "host" if f.stem == "ssh" else "client"
                    ),
                    brand=fp.get("device_vendor", ""),
                    original_type=fp.get("device_type", ""),
                    role=ROLE.get(fp.get("device_type", "").strip(), ""),
                    os=fp.get("os_class", ""),
                    status="converted" if ok else "unsupported_input",
                    reason="" if ok else "保留消息类型和组合条件，当前采集字段不完整",
                )


def librenms(b):
    p = b.root / "librenms"
    b.source(
        "librenms", "LibreNMS", "https://github.com/librenms/librenms", "GPL-3.0", p
    )
    licenses(b, "librenms", p)
    for f in sorted((p / "resources/definitions/os_detection").glob("*.yaml")):
        b.raw("librenms", f)
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except yaml.YAMLError as e:
            b.rule("librenms", f.name, f.stem, status="invalid_data", reason=str(e))
            continue
        ds = d.get("discovery", [])
        ds = ds if isinstance(ds, list) else [ds]
        if not ds:
            b.rule(
                "librenms",
                f.name,
                d.get("text", f.stem),
                status="unsupported_input",
                reason="需要 PHP 或额外管理查询",
            )
            continue
        for i, part in enumerate(ds):
            cs = []
            ok = isinstance(part, dict)
            if ok:
                # Keep OR alternatives as separate rules; unsupported compound structures remain dormant.
                keys = list(part)
                if len(keys) == 1 and keys[0] in [
                    "sysObjectID",
                    "sysDescr",
                    "sysDescr_regex",
                ]:
                    key = keys[0]
                    vs = part[key] if isinstance(part[key], list) else [part[key]]
                    for j, v in enumerate(vs):
                        if not isinstance(v, str):
                            b.rule(
                                "librenms",
                                f"{f.name}:{i}:{j}",
                                d.get("text", f.stem),
                                status="invalid_data",
                                reason="检测条件不是字符串",
                            )
                            continue
                        field = (
                            "snmp_sysoid" if key == "sysObjectID" else "snmp_sysdescr"
                        )
                        op = (
                            "oid_prefix"
                            if key == "sysObjectID"
                            else ("regex" if key.endswith("regex") else "contains")
                        )
                        pattern = v
                        if op == "regex":
                            m = re.fullmatch(r"/(.*)/([ims]*)", v, re.S)
                            if m:
                                pattern = ("(?" + m[2] + ")" if m[2] else "") + m[1]
                        b.rule(
                            "librenms",
                            f"{f.name}:{i}:{j}",
                            d.get("text", f.stem),
                            [cond(field, pattern, op)],
                            protocol="snmp",
                            direction="server",
                            os=d.get("text", ""),
                            status="converted",
                            reason="",
                        )
                    continue
            b.rule(
                "librenms",
                f"{f.name}:{i}",
                d.get("text", f.stem),
                status="unsupported_input",
                reason="需要尚未支持的 SNMP 组合查询",
            )


def whatweb(b):
    p = b.root / "whatweb"
    b.source(
        "whatweb", "WhatWeb", "https://github.com/urbanadventurer/WhatWeb", "GPL-2.0", p
    )
    licenses(b, "whatweb", p)
    for f in sorted((p / "plugins").glob("*.rb")):
        b.raw("whatweb", f)
        s = f.read_text(errors="replace")
        name = re.search(r"^\s*name\s+[\"\']([^\"\']+)", s, re.M)
        name = name[1] if name else f.stem
        # Only a single literal condition with no executable hooks is converted.
        region = re.search(r"(?ms)^\s*matches\s*\[\s*\n(.*?)^\s*\]\s*$", s)
        static = "\n".join(
            line
            for line in (region[1] if region else "").splitlines()
            if not line.lstrip().startswith("#")
        )
        blocks = re.findall(r"\{([^{}]+)\}", static, re.S)
        found = False
        for i, part in enumerate(blocks):
            keys = re.findall(r":(\w+)\s*=>", part)
            if not keys or not set(keys) <= {
                "text",
                "string",
                "name",
                "certainty",
                "search",
            }:
                continue
            m = re.search(r":text\s*=>\s*([\"\'])(.*?)\1", part, re.S)
            if not m:
                continue
            field = "http_body"
            search = re.search(r":search\s*=>\s*([\"\'])(.*?)\1", part, re.S)
            if "search" in keys:
                if not search:
                    continue
                field = {
                    "body": "http_body",
                    "headers[server]": "http_server",
                    "headers[www-authenticate]": "http_www_authenticate",
                    "title": "http_title",
                }.get(search[2])
                if not field:
                    continue
            if not m[2]:
                continue
            found = True
            b.rule(
                "whatweb",
                f"{f.name}:{i}",
                name,
                [cond(field, m[2], "contains")],
                protocol="http",
                direction="server",
                status=(
                    "unsupported_syntax"
                    if "\\" in m[2] or "#{" in m[2]
                    else "converted"
                ),
                reason="Ruby 字符串需人工适配" if "\\" in m[2] or "#{" in m[2] else "",
            )
        # Account for each plugin even when only some match alternatives were convertible.
        b.rule(
            "whatweb",
            f.name + ":plugin",
            name,
            status="unsupported_syntax",
            reason="插件的其余 Ruby 匹配、请求或动态条件不在运行时执行",
        )


def openwrt(b):
    p = b.root / "toh.complete.json"
    s = b.source(
        "openwrt",
        "OpenWrt Table of Hardware",
        "https://toh.openwrt.org/",
        "CC-BY-SA-4.0",
        status="registered",
    )
    if not p.exists():
        s["reason"] = "尚未下载硬件目录"
        return
    try:
        d = json.loads(p.read_text())
    except ValueError:
        s["reason"] = "硬件目录下载不完整"
        return
    b.provenance["openwrt/LICENSE"] = (b.root / "openwrt-LICENSE").read_text()
    b.provenance["openwrt/NOTICE"] = (
        "OpenWrt wiki contributors. Source: https://openwrt.org/toh/hwdata/start . CC-BY-SA-4.0. Converted to device model dictionary; no independent network evidence."
    )
    b.provenance["openwrt/toh.json"] = p.read_text()
    s["version"] = hashlib.sha256(p.read_bytes()).hexdigest()
    rows = (
        d
        if isinstance(d, list)
        else [dict(zip(d["columns"], row)) for row in d.get("entries", [])]
    )
    for i, x in enumerate(rows):
        brand = x.get("brand", x.get("Brand", ""))
        model = x.get("model", x.get("Model", ""))
        brand = brand if isinstance(brand, str) else ""
        model = model if isinstance(model, str) else ""
        device_type = str(x.get("devicetype") or "").lower()
        role = (
            "router"
            if "router" in device_type
            else (
                "access_point"
                if "access point" in device_type
                else (
                    "switch"
                    if "switch" in device_type
                    else "nas" if "nas" in device_type else ""
                )
            )
        )
        hardware = x.get("version") or ""
        hardware = hardware if isinstance(hardware, str) else ""
        b.rule(
            "openwrt",
            str(x.get("deviceid") or i),
            brand + " " + model,
            brand=brand,
            model=model,
            hardware_version=hardware,
            role=role,
            status="dictionary" if model else "invalid_data",
            reason="型号目录，不能作为独立网络证据" if model else "缺少型号",
        )


def p0f(b):
    p = b.root / "p0f"
    s = b.source(
        "p0f",
        "p0f",
        "https://github.com/p0f/p0f",
        "LGPL-2.1",
        p if p.exists() else None,
    )
    fp = p / "p0f.fp" if (p / "p0f.fp").exists() else b.root / "p0f.fp"
    if not fp.exists():
        s["reason"] = "尚未下载协议栈指纹"
        return
    raw = fp.read_text()
    b.provenance["p0f/p0f.fp"] = raw
    s["version"] = "4abbd20ecd7421461e360c77a98dff98e08a8b10"
    b.provenance["p0f/COPYING"] = (b.root / "p0f-COPYING").read_text()
    b.provenance["p0f/README"] = (b.root / "p0f-README").read_text()
    if p.exists():
        licenses(b, "p0f", p)
    label = ""
    section = ""
    for i, line in enumerate(raw.splitlines()):
        if line.startswith("["):
            section = line
        if line.startswith("label"):
            label = line.partition("=")[2].strip()
        if re.match(r"^sig\s*=", line):
            b.rule(
                "p0f",
                str(i),
                label,
                [cond("tcp_signature", line.partition("=")[2].strip(), "exact")],
                protocol=section,
                direction="client" if "request" in section else "server",
                status="unsupported_input",
                reason="需要完整 p0f 特征与通配匹配，不能用单一 TTL 替代",
            )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    b = Builder(a.snapshots)
    for convert in [recog, satori, librenms, whatweb, openwrt, p0f]:
        convert(b)
    s = b.source(
        "nmap",
        "Nmap",
        "https://github.com/nmap/nmap",
        "NPSL",
        status="license_required",
        reason="主动探测数据；未授权打包",
    )
    s.update(
        {
            k: v
            for k, v in json.loads(
                (Path(__file__).parent / "source-assessments.json").read_text()
            )["nmap"].items()
            if k != "assessment_files"
        }
    )
    b.source(
        "fingerbank-current",
        "Fingerbank 当前服务",
        "https://www.fingerbank.org/",
        "commercial-service",
        status="license_required",
        reason="需配置服务授权；与历史公开快照分开统计",
    )
    a.output.mkdir(parents=True, exist_ok=True)
    (a.output / "catalog-input.json").write_text(
        json.dumps(b.finish(), ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    (a.output / "multisource-provenance.json").write_text(
        json.dumps(b.provenance, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    print(
        json.dumps(
            {
                "sources": len(b.sources),
                "records": len(b.rules),
                "upstream_files": len(b.provenance),
            }
        )
    )


if __name__ == "__main__":
    main()
