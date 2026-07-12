import type { Ref } from 'vue'
import { useSensitiveVisibility } from './useSensitiveVisibility'

const visible: Ref<boolean> = useSensitiveVisibility()

void visible
