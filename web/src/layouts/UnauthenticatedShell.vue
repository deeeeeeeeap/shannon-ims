<script setup lang="ts">
import LoadingScreen from '../components/LoadingScreen.vue'
import SwitchDark from '../components/SwitchDark.vue'

defineProps({
  isDark: {
    type: Boolean,
    required: true
  }
})

const emit = defineEmits(['toggle-theme'])
</script>

<template>
  <div class="h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-950 transition-colors duration-300">
    <div class="absolute top-4 right-4 z-50">
      <SwitchDark :is-dark="isDark" @toggle="(e) => emit('toggle-theme', e)" />
    </div>
    <router-view v-slot="{ Component }">
      <Suspense>
        <template #default>
          <component :is="Component" />
        </template>
        <template #fallback>
          <LoadingScreen />
        </template>
      </Suspense>
    </router-view>
  </div>
</template>
