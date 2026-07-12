<script setup lang="ts">
defineProps<{
  rows?: number
}>()
</script>

<template>
  <div class="ui-surface rounded-2xl p-6">
    <el-skeleton :rows="rows || 6" animated />
  </div>
</template>
