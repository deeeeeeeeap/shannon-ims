package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	yaml "gopkg.in/yaml.v3"
)

const (
	apiDocsUIPath      = "/api/docs"
	apiOpenAPIYAMLPath = "/api/openapi.yaml"
	apiOpenAPIJSONPath = "/api/openapi.json"
)

type apiDocsLinks struct {
	SwaggerUI   string `json:"swagger_ui"`
	OpenAPIYAML string `json:"openapi_yaml"`
	OpenAPIJSON string `json:"openapi_json"`
}

//go:embed openapi.vohive.yaml
var openAPISpecYAML []byte

//go:embed all:docs_assets/swagger-ui
var swaggerUIAssetEmbedFS embed.FS

var (
	openAPISpecJSONOnce sync.Once
	openAPISpecJSON     []byte
	openAPISpecJSONErr  error
)

func currentAPIDocsLinks() apiDocsLinks {
	return apiDocsLinks{
		SwaggerUI:   apiDocsUIPath,
		OpenAPIYAML: apiOpenAPIYAMLPath,
		OpenAPIJSON: apiOpenAPIJSONPath,
	}
}

func loadOpenAPISpecJSON() ([]byte, error) {
	openAPISpecJSONOnce.Do(func() {
		var raw any
		if err := yaml.Unmarshal(openAPISpecYAML, &raw); err != nil {
			openAPISpecJSONErr = fmt.Errorf("parse openapi yaml: %w", err)
			return
		}
		encoded, err := json.Marshal(normalizeYAMLValue(raw))
		if err != nil {
			openAPISpecJSONErr = fmt.Errorf("marshal openapi json: %w", err)
			return
		}
		openAPISpecJSON = encoded
	})
	if openAPISpecJSONErr != nil {
		return nil, openAPISpecJSONErr
	}
	return openAPISpecJSON, nil
}

func normalizeYAMLValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, inner := range typed {
			out[k] = normalizeYAMLValue(inner)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for k, inner := range typed {
			out[fmt.Sprint(k)] = normalizeYAMLValue(inner)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, inner := range typed {
			out[i] = normalizeYAMLValue(inner)
		}
		return out
	default:
		return v
	}
}

func (s *Server) handleOpenAPIYAML(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openAPISpecYAML)
}

func (s *Server) handleOpenAPIJSON(c *gin.Context) {
	payload, err := loadOpenAPISpecJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "生成 OpenAPI JSON 失败: " + err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", payload)
}

func (s *Server) handleDocsAsset(c *gin.Context) {
	assetPath := strings.TrimPrefix(c.Param("filepath"), "/")
	if assetPath == "" {
		c.String(http.StatusNotFound, "Not Found")
		return
	}
	assetPath = path.Clean(assetPath)
	if assetPath == "." || strings.HasPrefix(assetPath, "../") {
		c.String(http.StatusNotFound, "Not Found")
		return
	}

	content, err := fs.ReadFile(swaggerUIAssetEmbedFS, path.Join("docs_assets/swagger-ui", assetPath))
	if err != nil {
		c.String(http.StatusNotFound, "Not Found")
		return
	}
	c.Data(http.StatusOK, docsAssetContentType(assetPath), content)
}

func docsAssetContentType(assetPath string) string {
	switch strings.ToLower(path.Ext(assetPath)) {
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".png":
		return "image/png"
	case ".svg":
		return "image/svg+xml"
	case ".txt", ".map":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func (s *Server) handleAPIDocs(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(apiDocsHTML))
}

const apiDocsHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>VoHive API Docs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" type="image/png" sizes="32x32" href="/api/docs/assets/favicon-32x32.png" />
  <link rel="icon" type="image/png" sizes="16x16" href="/api/docs/assets/favicon-16x16.png" />
  <link rel="stylesheet" href="/api/docs/assets/swagger-ui.css" />
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --panel: #ffffff;
      --panel-2: #e9eef7;
      --text: #132238;
      --muted: #62748a;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --border: #dbe5f0;
      --danger: #b42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 24%),
        radial-gradient(circle at top right, rgba(31, 41, 55, 0.08), transparent 18%),
        linear-gradient(180deg, #f7fbff 0%, var(--bg) 100%);
      color: var(--text);
      min-height: 100vh;
    }
    .page {
      width: min(1400px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 36px;
    }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 20px;
      align-items: start;
      margin-bottom: 20px;
      padding: 24px;
      border: 1px solid rgba(255,255,255,0.55);
      border-radius: 24px;
      background: rgba(255,255,255,0.86);
      box-shadow: 0 24px 50px rgba(15, 23, 42, 0.08);
      backdrop-filter: blur(12px);
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.10);
      color: var(--accent-strong);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 14px 0 10px;
      font-size: clamp(32px, 5vw, 54px);
      line-height: 0.95;
      letter-spacing: -0.04em;
    }
    .subtitle {
      max-width: 760px;
      margin: 0;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.6;
    }
    .hero-actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .btn {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      transition: transform .18s ease, box-shadow .18s ease, background .18s ease;
    }
    .btn:hover { transform: translateY(-1px); }
    .btn-primary {
      background: linear-gradient(135deg, #0f766e 0%, #115e59 100%);
      color: #fff;
      box-shadow: 0 12px 28px rgba(15, 118, 110, 0.24);
    }
    .btn-secondary {
      background: rgba(15, 23, 42, 0.06);
      color: var(--text);
    }
    .status-card {
      margin-bottom: 18px;
      border-radius: 20px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.9);
      padding: 18px 20px;
      box-shadow: 0 18px 36px rgba(15, 23, 42, 0.05);
    }
    .status-card[hidden] { display: none; }
    .status-title {
      margin: 0 0 6px;
      font-size: 18px;
      font-weight: 700;
    }
    .status-message {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      white-space: pre-line;
    }
    .status-card.error .status-title { color: var(--danger); }
    .status-card.ready .status-title { color: var(--accent-strong); }
    .status-meta {
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--panel-2);
    }
    #swagger-ui {
      border-radius: 24px;
      overflow: hidden;
      background: var(--panel);
      border: 1px solid rgba(219,229,240,0.9);
      box-shadow: 0 28px 60px rgba(15, 23, 42, 0.08);
    }
    .swagger-ui .topbar { display: none; }
    @media (max-width: 900px) {
      .page { width: min(100vw - 18px, 1400px); padding-top: 14px; }
      .hero { grid-template-columns: 1fr; padding: 18px; }
      .hero-actions { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <div>
        <div class="eyebrow">VoHive OpenAPI</div>
        <h1>主服务 API 文档</h1>
        <p class="subtitle">文档页会直接读取当前浏览器里的 VoHive 登录 token，并自动注入到 Swagger UI 的请求里。你可以在这里浏览接口、查看 schema、直接试调用。</p>
      </div>
      <div class="hero-actions">
        <a class="btn btn-secondary" href="/#/settings">返回系统设置</a>
        <a class="btn btn-primary" href="/#/login">前往登录</a>
      </div>
    </section>

    <section id="status-card" class="status-card" aria-live="polite">
      <h2 id="status-title" class="status-title">正在准备 API 文档</h2>
      <p id="status-message" class="status-message">正在检查当前浏览器的登录状态。</p>
      <div id="status-meta" class="status-meta"></div>
    </section>

    <div id="swagger-ui"></div>
  </div>

  <script src="/api/docs/assets/swagger-ui-bundle.js"></script>
  <script src="/api/docs/assets/swagger-ui-standalone-preset.js"></script>
  <script>
    (function () {
      var OPENAPI_JSON_URL = '/api/openapi.json';
      var LOGIN_URL = '/#/login';
      var SETTINGS_URL = '/#/settings';
      var token = '';
      var statusCard = document.getElementById('status-card');
      var statusTitle = document.getElementById('status-title');
      var statusMessage = document.getElementById('status-message');
      var statusMeta = document.getElementById('status-meta');
      var swaggerRoot = document.getElementById('swagger-ui');

      function setStatus(kind, title, message, meta) {
        statusCard.className = 'status-card ' + (kind || '');
        statusTitle.textContent = title;
        statusMessage.textContent = message;
        statusMeta.innerHTML = '';
        (meta || []).forEach(function (item) {
          var pill = document.createElement('span');
          pill.className = 'status-pill';
          pill.textContent = item;
          statusMeta.appendChild(pill);
        });
      }

      function showLoginHint(reason) {
        swaggerRoot.innerHTML = '';
        setStatus(
          'error',
          '当前还没有可用的登录 token',
          reason + '\n\n请先在 VoHive Web 控制台完成登录，然后重新打开这个页面。',
          ['文档页本身公开可访问', 'OpenAPI 规格仍需 Bearer 鉴权']
        );
      }

      function showLoadError(message, status) {
        swaggerRoot.innerHTML = '';
        var meta = [];
        if (status) {
          meta.push('HTTP ' + status);
        }
        meta.push('规格源 ' + OPENAPI_JSON_URL);
        setStatus('error', 'OpenAPI 规格加载失败', message, meta);
      }

      try {
        token = String(localStorage.getItem('token') || '').trim();
      } catch (err) {
        token = '';
      }

      if (!token) {
        showLoginHint('当前浏览器本地存储中没有发现 token。');
        return;
      }

      setStatus('ready', '正在加载 OpenAPI 规格', '已检测到登录 token，正在向主服务请求受保护的 OpenAPI JSON。', ['Bearer token 已就绪']);

      fetch(OPENAPI_JSON_URL, {
        headers: {
          Authorization: 'Bearer ' + token
        },
        credentials: 'same-origin'
      })
        .then(function (res) {
          if (!res.ok) {
            var err = new Error(res.status === 401 ? '当前登录状态已失效，请重新登录后再打开文档页。' : '主服务返回了异常状态，暂时无法加载文档。');
            err.status = res.status;
            throw err;
          }
          return res.json();
        })
        .then(function (spec) {
          setStatus('ready', 'OpenAPI 已就绪', '文档已载入。下面的 Try it out 请求会自动附带当前 Bearer token。', ['规格源 ' + OPENAPI_JSON_URL, 'Try it out 已注入 Authorization']);
          window.ui = SwaggerUIBundle({
            spec: spec,
            dom_id: '#swagger-ui',
            deepLinking: true,
            persistAuthorization: true,
            displayRequestDuration: true,
            tryItOutEnabled: true,
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
            layout: 'BaseLayout',
            requestInterceptor: function (req) {
              req.headers = req.headers || {};
              if (!req.headers.Authorization) {
                req.headers.Authorization = 'Bearer ' + token;
              }
              return req;
            },
            onComplete: function () {
              try {
                window.ui.preauthorizeApiKey('BearerAuth', token);
              } catch (err) {
                console.warn('[VoHive Docs] preauthorizeApiKey failed', err);
              }
              try {
                window.ui.authActions.authorize({
                  BearerAuth: {
                    name: 'BearerAuth',
                    schema: {
                      type: 'http',
                      scheme: 'bearer',
                      bearerFormat: 'SessionToken'
                    },
                    value: token
                  }
                });
              } catch (err) {
                console.warn('[VoHive Docs] authActions.authorize failed', err);
              }
            }
          });
        })
        .catch(function (err) {
          if (err && err.status === 401) {
            showLoginHint('当前 token 已过期或无效。');
            return;
          }
          showLoadError(err && err.message ? err.message : '未知错误', err && err.status ? err.status : '');
        });
    })();
  </script>
</body>
</html>`
