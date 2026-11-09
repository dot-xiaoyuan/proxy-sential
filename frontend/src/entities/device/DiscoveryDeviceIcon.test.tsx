import {render,screen,cleanup} from '@testing-library/react'
import {afterEach,expect,it} from 'vitest'
import {DiscoveryDeviceIcon} from './DiscoveryDeviceIcon'
afterEach(cleanup)
it('distinguishes equipment kinds and keeps an address-only candidate neutral',()=>{
  const {rerender}=render(<DiscoveryDeviceIcon type="access_point" />)
  expect(screen.getByRole('img',{name:'无线接入点'})).toHaveAttribute('data-device-kind','access_point')
  rerender(<DiscoveryDeviceIcon type="printer" />)
  expect(screen.getByRole('img',{name:'打印机'})).toHaveAttribute('data-device-kind','printer')
  rerender(<DiscoveryDeviceIcon type="camera" />)
  expect(screen.getByRole('img',{name:'摄像机'})).toHaveAttribute('data-device-kind','camera')
  rerender(<DiscoveryDeviceIcon type="voice_gateway" />)
  expect(screen.getByRole('img',{name:'语音网关'})).toHaveAttribute('data-device-kind','voice_gateway')
  rerender(<DiscoveryDeviceIcon />)
  expect(screen.getByRole('img',{name:'设备地址'})).toHaveAttribute('data-device-kind','generic')
})
