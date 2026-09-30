import { useSearchParams } from 'react-router-dom'

export function useUrlState(key: string, fallback: string, allowed?: readonly string[], resetKeys?: readonly string[]) {
  const [params,setParams] = useSearchParams()
  const raw=params.get(key)
  const value=raw && (!allowed || allowed.includes(raw)) ? raw : fallback
  const setValue=(value:string)=>setParams(current=>{const next=new URLSearchParams(current);if(value)next.set(key,value);else next.delete(key);for(const name of [...next.keys()])if(name!==key&&(resetKeys?resetKeys.includes(name):key!=='tab'&&(name==='cursor'||name==='page'||name.endsWith('_page'))))next.delete(name);return next})
  return [value,setValue] as const
}
