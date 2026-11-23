import { Popover, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { observedTimeLabel, observedTimeTitle } from '../../shared/ui/observedTime'

/** The primary line is always an address. Missing values never become names. */
export function DeviceAddress({ip,name,mac,addresses=[],historicalIP,lastObservedIP,lastObservedAt,href}:{ip?:string;name?:string;mac?:string;addresses?:string[];historicalIP?:string;lastObservedIP?:string;lastObservedAt?:string;href?:string}) {
 if(name===ip||name===mac||name===lastObservedIP)name=undefined
 const others=addresses.filter(address=>address!==ip)
 const address = ip || lastObservedIP
 const lastSeen = !ip && lastObservedIP ? observedTimeLabel(lastObservedAt) : ''
 return <div className="center-device-identity">
  {address && <div className="center-address-line">
   {ip && href ? <Link className="center-primary-ip" title={ip} to={href}>{ip}</Link> : <strong className="center-primary-ip" title={address}>{address}</strong>}
   {ip && <Typography.Text className="device-copy-control" copyable={{text:ip}}/>}
   {ip && others.length > 0 && <Popover title="其他有效地址" content={<div className="center-addresses">{others.map(address=><Typography.Text key={address} copyable={{text:address}}>{address}</Typography.Text>)}</div>}><button className="center-more-addresses">+{others.length}</button></Popover>}
  </div>}
  {!ip && lastObservedIP && <span className="center-historical-ip" title={observedTimeTitle(lastObservedAt)}>最后观测 IP{lastSeen && ` · ${lastSeen}`}</span>}
  {(name || mac) && <div className="center-device-secondary">{name&&<span title={name}>{name}</span>}{mac&&<span className="mono" title={mac}>{mac}</span>}</div>}
  {!address && historicalIP && <span className="center-historical-ip" title={historicalIP}>历史 IP：{historicalIP}</span>}
  {!ip && href && <Link to={href}>查看详情</Link>}
 </div>
}
