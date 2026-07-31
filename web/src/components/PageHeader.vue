<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 sm:mb-8">
    <div>
      <!-- h1, not h2: this is the only page-level heading each view renders, and
           starting the document outline at h2 leaves a screen reader with no top
           level to navigate to. -->
      <h1 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400">{{ title }}</h1>
      <p v-if="subtitle" class="text-gray-500 dark:text-gray-400 mt-1">{{ subtitle }}</p>
    </div>
    <slot name="actions" />
  </div>
</template>
