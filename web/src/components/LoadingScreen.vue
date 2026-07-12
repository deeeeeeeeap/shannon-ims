<script setup lang="ts">
defineProps({
  title: {
    type: String,
    default: '正在加载…'
  },
  subtitle: {
    type: String,
    default: '首次打开会稍慢，资源缓存后会更快'
  }
})
</script>

<template>
  <div class="min-h-[260px] w-full flex items-center justify-center">
    <div class="w-full max-w-md rounded-2xl border border-white/10 bg-white/5 dark:bg-white/5 backdrop-blur-xl p-6 shadow-2xl">
      <div class="flex items-center gap-3">
        <div class="w-11 h-11 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-sm font-extrabold flex items-center justify-center shadow-lg shadow-indigo-500/25">
          VH
        </div>
        <div class="min-w-0">
          <div class="text-base font-extrabold text-gray-900 dark:text-white truncate">{{ title }}</div>
          <div class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 truncate">{{ subtitle }}</div>
        </div>
      </div>

      <div class="mt-5 flex items-center gap-3">
        <div class="text-xs font-semibold text-gray-500 dark:text-gray-400 tracking-wide">loading</div>
        <div class="h-2 flex-1 rounded-full bg-gray-200/50 dark:bg-white/10 overflow-hidden relative">
          <div class="absolute inset-0 -translate-x-[60%] bg-gradient-to-r from-transparent via-white/35 to-transparent animate-[loader-shimmer_1.05s_ease-in-out_infinite]"></div>
        </div>
        <div class="w-4 h-4 rounded-full border-2 border-white/25 border-t-white animate-spin"></div>
      </div>
    </div>
  </div>
</template>

<style>
@keyframes loader-shimmer {
  0% {
    transform: translateX(-60%);
  }
  100% {
    transform: translateX(60%);
  }
}
</style>
