<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <div class="p-12 text-center rounded-2xl border border-dashed border-gray-300 dark:border-gray-700 ui-surface-muted">
    <div class="mx-auto w-12 h-12 rounded-2xl bg-gray-100/80 dark:bg-white/5 flex items-center justify-center text-gray-500 dark:text-gray-300">
      <slot name="icon">
        <span class="text-xl font-bold">∅</span>
      </slot>
    </div>
    <div class="mt-4 text-sm font-bold text-gray-700 dark:text-gray-200">{{ title }}</div>
    <div v-if="subtitle" class="mt-1 text-xs text-gray-400">{{ subtitle }}</div>
    <div class="mt-5 flex items-center justify-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>
