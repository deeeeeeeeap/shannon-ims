<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()
</script>

<template>
  <!-- Was a 48px dashed-border box with a large centred set-theory glyph in a
       rounded tile. The glyph carried no meaning and the dashed frame drew as much
       attention as real content. An empty list should be quiet: say what is missing
       and offer the action, nothing more. -->
  <div class="empty-state">
    <p class="empty-state-title">{{ title }}</p>
    <p v-if="subtitle" class="empty-state-subtitle">{{ subtitle }}</p>
    <div class="empty-state-actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped>
.empty-state {
  padding: 2.5rem 1.5rem;
  text-align: center;
}

.empty-state-title {
  margin: 0;
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--ui-text-muted);
}

.empty-state-subtitle {
  margin: 0.375rem 0 0;
  font-size: 0.75rem;
  color: var(--ui-text-faint);
}

/* Collapses to nothing when the slot is unused, so an empty state with no action
   does not reserve a gap. */
.empty-state-actions:not(:empty) {
  margin-top: 1rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}
</style>
