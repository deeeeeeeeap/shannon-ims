import { api } from '../stores/auth'
import { callService } from './http'
import type {
  UpstreamProxy,
  UpstreamProxyCountry,
  UpstreamProxyCountryRule,
  UpstreamProxyCountryRulePayload
} from '../types/api'

// 前置代理 API 服务层
export const upstreamProxyService = {
  // 列出所有前置代理
  list() {
    return callService(async () => {
      const res = await api.get('/upstream-proxies')
      return (res.data || []) as UpstreamProxy[]
    })
  },

  // 新增前置代理
  create(proxy: UpstreamProxy) {
    return callService(async () => {
      await api.post('/upstream-proxies', proxy)
      return true
    })
  },

  // 更新前置代理
  update(id: string, proxy: Partial<UpstreamProxy>) {
    return callService(async () => {
      await api.put(`/upstream-proxies/${id}`, proxy)
      return true
    })
  },

  // 删除前置代理
  remove(id: string) {
    return callService(async () => {
      await api.delete(`/upstream-proxies/${id}`)
      return true
    })
  },

  // 列出可配置国家及其 MCC 分组
  listCountries() {
    return callService(async () => {
      const res = await api.get('/upstream-proxy-countries')
      return (res.data || []) as UpstreamProxyCountry[]
    })
  },

  // 列出国家代理规则
  listCountryRules() {
    return callService(async () => {
      const res = await api.get('/upstream-proxy-country-rules')
      return (res.data || []) as UpstreamProxyCountryRule[]
    })
  },

  // 配置一个国家的前置代理规则
  upsertCountryRule(countryCode: string, payload: UpstreamProxyCountryRulePayload) {
    return callService(async () => {
      const res = await api.put(`/upstream-proxy-country-rules/${encodeURIComponent(countryCode)}`, payload)
      return res.data as UpstreamProxyCountryRule
    })
  },

  // 删除国家规则，删除后该国家默认直连
  deleteCountryRule(countryCode: string) {
    return callService(async () => {
      await api.delete(`/upstream-proxy-country-rules/${encodeURIComponent(countryCode)}`)
      return true
    })
  }
}
