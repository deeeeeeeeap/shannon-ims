<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <!-- The title was 30px, bold, and filled with a gradient via background-clip:text
       on every single page. At that size it competed with the data underneath, and
       the gradient added nothing an operator could read. It is now 17px semibold
       with the subtitle on the same line, and a rule underneath ties it to the
       content rather than leaving it floating in whitespace. -->
  <div class="page-header">
    <div class="min-w-0">
      <div class="flex items-baseline gap-2.5 flex-wrap">
        <h1 class="page-header-title">{{ title }}</h1>
        <p v-if="subtitle" class="page-header-subtitle">{{ subtitle }}</p>
      </div>
    </div>
    <div class="flex items-center gap-2 flex-shrink-0">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding-bottom: 0.875rem;
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--ui-border-solid);
  flex-wrap: wrap;
}

.page-header-title {
  font-size: 1.0625rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text);
  margin: 0;
}

.page-header-subtitle {
  font-size: 0.8125rem;
  color: var(--ui-text-muted);
  margin: 0;
}
</style>
