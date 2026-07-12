import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { AppError } from '../types/domain'
import type {
  UpstreamProxy,
  UpstreamProxyCountry,
  UpstreamProxyCountryRule,
  UpstreamProxyCountryRulePayload
} from '../types/api'
import { upstreamProxyService } from '../services/upstream-proxy'

export const useUpstreamProxyStore = defineStore('upstreamProxy', () => {
  const proxies = ref<UpstreamProxy[]>([])
  const countries = ref<UpstreamProxyCountry[]>([])
  const countryRules = ref<UpstreamProxyCountryRule[]>([])

  const loading = ref(false)
  const lastOkAt = ref<number | null>(null)
  const error = ref<AppError | null>(null)

  // 同时拉取代理列表、国家列表和国家规则
  async function fetchAll() {
    loading.value = true
    error.value = null
    const [proxiesResult, countriesResult, rulesResult] = await Promise.all([
      upstreamProxyService.list(),
      upstreamProxyService.listCountries(),
      upstreamProxyService.listCountryRules()
    ])
    if (proxiesResult.ok) {
      proxies.value = proxiesResult.data
    } else {
      error.value = proxiesResult.error
    }
    if (countriesResult.ok) {
      countries.value = countriesResult.data
    } else if (!error.value) {
      error.value = countriesResult.error
    }
    if (rulesResult.ok) {
      countryRules.value = rulesResult.data
    } else if (!error.value) {
      error.value = rulesResult.error
    }
    if (proxiesResult.ok && countriesResult.ok && rulesResult.ok) {
      lastOkAt.value = Date.now()
    }
    loading.value = false
    return proxiesResult
  }

  async function createProxy(proxy: UpstreamProxy) {
    return upstreamProxyService.create(proxy)
  }

  async function updateProxy(id: string, proxy: Partial<UpstreamProxy>) {
    return upstreamProxyService.update(id, proxy)
  }

  async function deleteProxy(id: string) {
    return upstreamProxyService.remove(id)
  }

  async function upsertCountryRule(countryCode: string, payload: UpstreamProxyCountryRulePayload) {
    return upstreamProxyService.upsertCountryRule(countryCode, payload)
  }

  async function deleteCountryRule(countryCode: string) {
    return upstreamProxyService.deleteCountryRule(countryCode)
  }

  // 获取某个代理的国家规则列表
  function getRulesForProxy(proxyId: string): UpstreamProxyCountryRule[] {
    return countryRules.value.filter(rule => rule.upstream_proxy_id === proxyId)
  }

  // 获取某个国家已配置的规则
  function getRuleForCountry(countryCode: string): UpstreamProxyCountryRule | null {
    const normalized = countryCode.trim().toUpperCase()
    return countryRules.value.find(rule => rule.country_code === normalized) ?? null
  }

  return {
    proxies,
    countries,
    countryRules,
    loading,
    lastOkAt,
    error,
    fetchAll,
    createProxy,
    updateProxy,
    deleteProxy,
    upsertCountryRule,
    deleteCountryRule,
    getRulesForProxy,
    getRuleForCountry
  }
})
