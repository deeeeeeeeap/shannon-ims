<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 sm:mb-8">
    <div>
      <h2 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400">{{ title }}</h2>
      <p v-if="subtitle" class="text-gray-500 dark:text-gray-400 mt-1">{{ subtitle }}</p>
    </div>
    <slot name="actions" />
  </div>
</template>
