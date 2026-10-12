import { render,screen,cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach,it,expect } from 'vitest'
import { DeviceAddress } from './DeviceAddress'
afterEach(cleanup)
it('keeps IP primary even with a name and multiple addresses',()=>{render(<MemoryRouter><DeviceAddress ip="192.0.2.1" name="Printer" mac="00:11:22:33:44:55" addresses={['192.0.2.1','2001:db8::1']} href="/devices/id"/></MemoryRouter>);expect(screen.getByRole('link',{name:'192.0.2.1'})).toHaveClass('center-primary-ip');expect(screen.getByText('Printer')).not.toHaveClass('center-primary-ip');expect(screen.getByRole('button',{name:'+1'})).toBeVisible()})
it('IPv6 uses the same primary element, tooltip and copy',()=>{const ip='2001:db8:abcd:1234:1234:5678:9012:abcd';render(<DeviceAddress ip={ip}/>);expect(screen.getByTitle(ip)).toHaveClass('center-primary-ip');expect(screen.getByRole('button',{name:/copy/i})).toBeVisible()})
it('never promotes a historical address or MAC into current IP',()=>{render(<DeviceAddress name="Printer" mac="00:11:22:33:44:55" historicalIP="192.0.2.1"/>);expect(document.querySelector('.center-primary-ip')).toBeNull();expect(screen.getByText('历史 IP：192.0.2.1')).toBeVisible()})
