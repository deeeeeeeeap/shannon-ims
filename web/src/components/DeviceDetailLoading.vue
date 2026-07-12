<template>
  <div class="ui-card p-6 overflow-hidden relative">
    <div class="shimmer-mask"></div>

    <div class="flex items-center gap-3 mb-6">
      <div class="skeleton-block h-11 w-11 rounded-xl"></div>
      <div class="min-w-0 flex-1 space-y-2">
        <div class="skeleton-block h-5 w-40 rounded-md"></div>
        <div class="skeleton-block h-3 w-56 rounded-md"></div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="ui-panel-muted p-4 space-y-3">
        <div class="skeleton-block h-3 w-20 rounded"></div>
        <div class="skeleton-block h-10 w-full rounded-lg"></div>
        <div class="skeleton-block h-3 w-3/4 rounded"></div>
        <div class="skeleton-block h-3 w-2/3 rounded"></div>
      </div>

      <div class="ui-panel-muted p-4 space-y-3">
        <div class="skeleton-block h-3 w-20 rounded"></div>
        <div class="skeleton-block h-4 w-full rounded"></div>
        <div class="skeleton-block h-4 w-11/12 rounded"></div>
        <div class="skeleton-block h-4 w-10/12 rounded"></div>
        <div class="skeleton-block h-4 w-9/12 rounded"></div>
      </div>

      <div class="ui-panel-muted p-4 space-y-3">
        <div class="skeleton-block h-3 w-20 rounded"></div>
        <div class="skeleton-block h-16 w-full rounded-lg"></div>
        <div class="skeleton-block h-3 w-5/6 rounded"></div>
      </div>
    </div>

    <div class="mt-5 text-xs text-gray-500 dark:text-gray-400 tracking-wide">正在加载设备...</div>
  </div>
</template>

<style scoped>
.skeleton-block {
  position: relative;
  background: rgba(148, 163, 184, 0.18);
}

html.dark .skeleton-block {
  background: rgba(148, 163, 184, 0.14);
}

.shimmer-mask {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(
    110deg,
    rgba(255, 255, 255, 0) 20%,
    rgba(255, 255, 255, 0.24) 48%,
    rgba(255, 255, 255, 0) 76%
  );
  transform: translateX(-65%);
  animation: device-detail-shimmer 1.25s ease-in-out infinite;
}

html.dark .shimmer-mask {
  background: linear-gradient(
    110deg,
    rgba(255, 255, 255, 0) 20%,
    rgba(255, 255, 255, 0.12) 48%,
    rgba(255, 255, 255, 0) 76%
  );
}

@keyframes device-detail-shimmer {
  0% {
    transform: translateX(-65%);
  }
  100% {
    transform: translateX(65%);
  }
}
</style>
