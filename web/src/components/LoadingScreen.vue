<script setup lang="ts">
defineProps({
  title: {
    type: String,
    default: '正在加载…'
  },
  subtitle: {
    type: String,
    default: ''
  }
})
</script>

<template>
  <!-- A loading state flashes past on every route change, so it should be quiet.
       This replaced a panel with a gradient "VH" tile, shadow-2xl, a shimmer sweep
       and a spinner all at once -- four effects competing for a moment that lasts
       under a second, and carrying the old brand mark. -->
  <div class="loading-screen" role="status" aria-live="polite">
    <div class="loading-bar" aria-hidden="true"><span /></div>
    <p class="loading-title">{{ title }}</p>
    <p v-if="subtitle" class="loading-subtitle">{{ subtitle }}</p>
  </div>
</template>

<style scoped>
.loading-screen {
  min-height: 220px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 2rem 1rem;
}

/* An indeterminate track: it says "working" without implying a percentage the app
   does not know. */
.loading-bar {
  width: 8rem;
  height: 2px;
  border-radius: 1px;
  background: var(--ui-border-solid);
  overflow: hidden;
}

.loading-bar span {
  display: block;
  width: 40%;
  height: 100%;
  border-radius: 1px;
  background: var(--ui-accent);
  animation: loading-slide 1.1s ease-in-out infinite;
}

@keyframes loading-slide {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(250%); }
}

.loading-title {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--ui-text-muted);
}

.loading-subtitle {
  margin: 0;
  font-size: 0.75rem;
  color: var(--ui-text-faint);
}

/* Reduced motion: hold the bar still and let the text carry the state, rather than
   animating at a slower speed that still moves. */
@media (prefers-reduced-motion: reduce) {
  .loading-bar span {
    animation: none;
    width: 100%;
    opacity: 0.5;
  }
}
</style>
