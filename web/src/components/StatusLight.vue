<script setup lang="ts">
import { computed } from 'vue'
import {
  statusLightAnimatedClass,
  statusLightSizeClass,
  statusLightToneClass,
  type StatusLightSize,
  type StatusLightTone
} from './statusLight'

const props = withDefaults(defineProps<{
  tone: StatusLightTone
  size?: StatusLightSize
  animated?: boolean
}>(), {
  size: 'sm',
  animated: true
})

const classes = computed(() => [
  'rounded-full inline-block flex-shrink-0',
  statusLightToneClass(props.tone),
  statusLightSizeClass(props.size),
  statusLightAnimatedClass(props.animated)
])
</script>

<template>
  <span aria-hidden="true" :class="classes" />
</template>
