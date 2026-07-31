import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiProxyTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:7575'

  return {
    plugins: [
      vue(),
      AutoImport({
        dts: 'src/auto-imports.d.ts',
        imports: ['vue', 'vue-router', 'pinia'],
        // importStyle: 'css' makes the resolver inject each component's own
        // stylesheet at its import site, so only the components actually used are
        // bundled. main.ts previously pulled element-plus/dist/index.css whole:
        // 341.8 KB covering 117 components, of which this app uses 31.
        //
        // The resolver is used rather than a hand-written list because several
        // components pull in styles that never appear in our templates (popper,
        // scrollbar, overlay, select-dropdown, message, collapse-transition), and
        // missing one shows up as subtly broken layout rather than an error.
        resolvers: [ElementPlusResolver({ importStyle: 'css' })]
      }),
      Components({
        dts: 'src/components.d.ts',
        resolvers: [
          ElementPlusResolver({
            importStyle: 'css'
          })
        ]
      })
    ],
    build: {
      rollupOptions: {
        output: {
          // Application code is deliberately NOT grouped here.
          //
          // Naming route code into fixed chunks (route-devices, route-sms, ...) made
          // Rollup treat them as shared chunks and hoist them into index.html as
          // modulepreload links, so opening the LOGIN page eagerly fetched 137 KB of
          // device-management code plus 36 KB of SMS code and their stylesheets --
          // for a screen with two inputs and a button. Leaving route code alone lets
          // Vite split it on the router's own import() boundaries, which is what
          // makes lazy routes actually lazy.
          //
          // Third-party grouping is still worth doing: these are large, change
          // rarely, and benefit from stable long-lived cache entries.
          // Third-party libraries are grouped; application code is not.
          //
          // Two things were tried here and rejected, both by measurement:
          //
          //   1. Naming route code (route-devices, route-sms, ...) turned those into
          //      shared chunks, which Vite then modulepreloads from index.html. The
          //      login page ended up fetching 137 KB of device-management code and
          //      36 KB of SMS code plus their stylesheets. Removing those names cut
          //      the eager set by ~208 KB and is kept.
          //
          //   2. Also un-grouping element-plus, to stop it being preloaded, folded
          //      it into `vendor` and produced a build that threw
          //      "Cannot access 'ze' before initialization" and rendered an empty
          //      page -- element-plus has internal circular imports that only
          //      resolve correctly when it stays in a chunk of its own.
          //
          // So element-plus keeps its own chunk. It is still preloaded on the login
          // page, which costs ~911 KB the login screen does not use; fixing that
          // needs the login route pulled out of the shared graph, not more chunk
          // renaming.
          manualChunks(id) {
            if (!id.includes('node_modules')) return

            // Only the stylesheets main.ts imports directly are grouped here, and
            // the list is explicit rather than a prefix match on "element-plus".
            //
            // Why they need their own group: they are ENTRY modules, so grouping them
            // with the library's JavaScript made that whole chunk an entry dependency
            // and ~14 KB of CSS dragged 757 KB of element-plus JS onto the login page.
            //
            // Why the list is explicit: matching every element-plus .css swept in the
            // per-component styles the resolver injects too (106 component classes,
            // 154 KB), which put the entire component stylesheet on the login page
            // instead of just the globals it actually needs.
            if (id.includes('element-plus') && id.endsWith('.css')) {
              const eager = [
                'theme-chalk/base.css',
                'theme-chalk/dark/css-vars.css',
                'theme-chalk/el-message.css',
                'theme-chalk/el-message-box.css',
                'theme-chalk/el-loading.css',
                'theme-chalk/el-overlay.css',
              ]
              const norm = id.replace(/\\/g, '/')
              if (eager.some(p => norm.includes(p))) return 'element-plus-globals-css'
              // Everything else is a per-component stylesheet: let it travel with the
              // chunk of the view that uses the component.
              return
            }

            if (id.includes('echarts') || id.includes('zrender') || id.includes('vue-echarts')) return 'echarts'
            if (id.includes('@element-plus/icons-vue')) return 'ep-icons'
            if (id.includes('element-plus')) return 'element-plus'
            if (id.includes('@vicons')) return 'vicons'
            if (id.includes('vue-router') || id.includes('pinia') || id.includes('/vue/')) return 'vue-core'
            return 'vendor'
          }
        }
      }
    },
    optimizeDeps: {
      // @vicons/fluent must be PRE-BUNDLED, not excluded. The package ships 10072
      // separate icon modules; excluding it makes the dev server transform them
      // one file at a time, which exhausts the Windows file-handle limit and kills
      // the process with EMFILE partway through startup. Pre-bundling reads them
      // once with esbuild instead.
      //
      // `npm run build` was never affected -- Rollup batches differently -- so CI
      // stayed green while local `npm run dev` could not boot.
      include: [
        '@vicons/fluent',
        '@element-plus/icons-vue',
        'element-plus',
        'element-plus/es',
        'echarts/core',
        'echarts/renderers',
        'echarts/lib/chart/line',
        'echarts/lib/component/grid',
        'echarts/lib/component/tooltip',
        'echarts/lib/component/legend',
        'echarts/lib/component/dataZoom',
        'vue-echarts'
      ]
    },
    server: {
      host: '0.0.0.0',
      port: 5173,
      strictPort: true,
      watch: {
        ignored: ['**/dist/**', '**/.git/**']
      },
      proxy: {
        '/api': {
          target: apiProxyTarget,
          changeOrigin: true,
          timeout: 120000,
          proxyTimeout: 120000
        }
      }
    }
  }
})
