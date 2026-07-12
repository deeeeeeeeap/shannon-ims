/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, any>
  export default component
}

declare module 'vue-virtual-scroller' {
  import type { DefineComponent } from 'vue'

  // RecycleScroller 的 props 类型
  interface RecycleScrollerProps<T = any> {
    items: T[]
    itemSize?: number | null
    keyField?: string
    direction?: 'vertical' | 'horizontal'
    buffer?: number
    pageMode?: boolean
    prerender?: number
    emitUpdate?: boolean
  }

  // RecycleScroller 的 slots 类型
  interface RecycleScrollerSlots<T = any> {
    default: (props: { item: T; index: number; active: boolean }) => any
    before?: () => any
    after?: () => any
  }

  export const RecycleScroller: new <T = any>() => {
    $props: RecycleScrollerProps<T>
    $slots: RecycleScrollerSlots<T>
  }

  export const DynamicScroller: DefineComponent<any, any, any>
  export const DynamicScrollerItem: DefineComponent<any, any, any>
}

declare module '*.css' {
  const content: string
  export default content
}
