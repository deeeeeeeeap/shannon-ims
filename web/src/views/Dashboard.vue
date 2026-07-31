<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import DeviceCard from '../components/DeviceCard.vue'
import PageHeader from '../components/PageHeader.vue'
import EmptyState from '../components/EmptyState.vue'
import ListSkeleton from '../components/ListSkeleton.vue'
import ErrorState from '../components/ErrorState.vue'
import RefreshButton from '../components/RefreshButton.vue'
import TrafficAnalysisPanel from '../components/TrafficAnalysisPanel.vue'
import { usePollingScheduler } from '../composables/usePollingScheduler'
import { useDashboardStore } from '../stores/dashboard'
import type { TrafficRange } from '../services/traffic'

const dashboard = useDashboardStore()
const router = useRouter()
const {
  devices,
  devicesLoading: loading,
  devicesLastOkAt,
  devicesError,
  analysis,
  analysisLoading,
  analysisLastOkAt,
  analysisError
} = storeToRefs(dashboard)

const lastUpdatedAt = ref<number | null>(null)

const analysisRange = ref<TrafficRange>('day')

const totalCount = computed(() => devices.value.length)
const onlineCount = computed(() => devices.value.filter(d => d?.healthy).length)
const offlineCount = computed(() => Math.max(0, totalCount.value - onlineCount.value))

async function fetchDevices() {
  await dashboard.fetchDevices()
  lastUpdatedAt.value = Date.now()
}

async function fetchTrafficAnalysis() {
  await dashboard.fetchAnalysis(analysisRange.value)
}

function handleAnalysisRangeChange(range: TrafficRange) {
  if (analysisRange.value === range) return
  analysisRange.value = range
  void fetchTrafficAnalysis()
}

function openDeviceOverview(id: string) {
  const deviceID = String(id || '').trim()
  if (!deviceID) return
  void router.push({
    name: 'Devices',
    query: {
      device: deviceID,
      tab: 'overview'
    }
  })
}

usePollingScheduler(fetchDevices, 5000, {
  immediate: true,
  maxIntervalMs: 30000,
  backgroundIntervalMs: 15000
})
usePollingScheduler(fetchTrafficAnalysis, 60000, {
  immediate: false,
  maxIntervalMs: 300000,
  backgroundIntervalMs: 120000
})

onMounted(() => {
  const win = window as Window & {
    requestIdleCallback?: (cb: IdleRequestCallback, opts?: IdleRequestOptions) => number
  }
  if (typeof win.requestIdleCallback === 'function') {
    win.requestIdleCallback(() => fetchTrafficAnalysis(), { timeout: 1500 })
  } else {
    setTimeout(fetchTrafficAnalysis, 800)
  }
})
</script>

<template>
  <div>
    <PageHeader title="设备监控" subtitle="实时查看设备状态与出口 IP">
      <template #actions>
        <RefreshButton :loading="loading" @click="fetchDevices" />
      </template>
    </PageHeader>

    <!-- One strip, not four cards.
         These are three related numbers plus a timestamp; giving each its own
         bordered panel with a 24px extrabold figure made four competing focal
         points out of a single summary. They now share one row, divided rather than
         boxed, at a size that reads as a readout instead of a headline.

         aria-live: the counts change on a 5s poll with no user action behind them,
         so without it a screen reader never learns a device dropped. -->
    <div class="stat-strip" role="status" aria-live="polite">
      <div class="stat">
        <span class="stat-label">设备总数</span>
        <span class="stat-value">{{ totalCount }}</span>
      </div>
      <div class="stat">
        <span class="stat-label">在线</span>
        <span class="stat-value text-success-600 dark:text-success-400">{{ onlineCount }}</span>
      </div>
      <div class="stat">
        <span class="stat-label">离线</span>
        <span class="stat-value" :class="offlineCount > 0 ? 'text-danger-600 dark:text-danger-400' : ''">{{ offlineCount }}</span>
      </div>
      <!-- aria-hidden: the clock ticks every poll and would talk over the counts,
           which are the part worth announcing. -->
      <div class="stat stat-timestamp" aria-hidden="true">
        <span class="stat-label">最近刷新</span>
        <span class="stat-value stat-value-clock">
          {{ lastUpdatedAt ? new Date(lastUpdatedAt).toLocaleTimeString() : '--:--:--' }}
        </span>
      </div>
    </div>

    <ErrorState
      v-if="devicesError"
      class="mb-6"
      title="设备列表加载失败"
      :message="devicesError.message"
      :status-code="devicesError.status"
      :request-method="devicesError.method"
      :request-url="devicesError.url"
      :last-success-at="devicesLastOkAt"
      retry-text="重试"
      @retry="fetchDevices"
    />

    <ListSkeleton v-if="loading && devices.length === 0" :rows="10" />

    <EmptyState v-else-if="devices.length === 0" title="暂无设备接入" subtitle="请先在设备管理中添加或接管设备" />

    <!-- gap-3, not gap-5. With panels this size a 20px gutter reads as a scatter of
         separate objects; 12px lets the grid read as one block of devices. -->
    <div v-else class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4 gap-3">
      <DeviceCard
        v-for="dev in devices"
        :key="dev.id"
        :device="dev"
        @open-device="openDeviceOverview"
      />
    </div>

    <TrafficAnalysisPanel
      v-if="devices.length > 0 || !loading"
      class="mt-6"
      :analysis="analysis"
      :loading="analysisLoading"
      :error="analysisError"
      :last-ok-at="analysisLastOkAt"
      :range="analysisRange"
      mode="global"
      @update:range="handleAnalysisRangeChange"
      @refresh="fetchTrafficAnalysis"
    />
  </div>
</template>

<style scoped>
/* Divided, not boxed: one bordered container with internal rules, so the four
   figures read as one summary line. */
.stat-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--ui-border-solid);
  border-radius: var(--ui-radius-md);
  background: var(--ui-surface-solid);
  margin-bottom: 1.25rem;
  overflow: hidden;
}

.stat {
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
}

.stat + .stat {
  border-left: 1px solid var(--ui-border-solid);
}

.stat-label {
  font-size: 0.6875rem;
  color: var(--ui-text-faint);
}

/* tabular-nums so a count changing from 9 to 10 does not shift the layout. */
.stat-value {
  font-size: 1.125rem;
  font-weight: 550;
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
  color: var(--ui-text);
}

.stat-value-clock {
  font-size: 0.8125rem;
  font-weight: 400;
  color: var(--ui-text-muted);
  font-feature-settings: 'tnum';
}

/* Two columns on narrow screens; the timestamp is the first thing to go. */
@media (max-width: 640px) {
  .stat-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .stat:nth-child(3) {
    border-left: 0;
  }

  .stat:nth-child(n + 3) {
    border-top: 1px solid var(--ui-border-solid);
  }
}
</style>
