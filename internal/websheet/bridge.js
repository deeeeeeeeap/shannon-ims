(function(){
  const callbackURL = {{CALLBACK_URL}};
  const absolutePathProxyPrefix = {{ABSOLUTE_PATH_PROXY_PREFIX}};
  const websheetToken = {{WEBSHEET_TOKEN}};
  const odsaStorageKey = "ts43-go.odsa.callbacks";
  const vowifiStorageKey = "vowifi-go.vowifi.callbacks";
  const shellBroadcastName = "vohive-websheet";
  const shellStorageKey = "vohive-websheet-complete";
  let attAddressCompletionPosted = false;

  function appendWebsheetToken(value) {
    if (!websheetToken || typeof value !== "string" || value.indexOf("/api/websheets/") !== 0) return value;
    const hashIndex = value.indexOf("#");
    const hash = hashIndex >= 0 ? value.slice(hashIndex) : "";
    const withoutHash = hashIndex >= 0 ? value.slice(0, hashIndex) : value;
    const sep = withoutHash.indexOf("?") >= 0 ? "&" : "?";
    return withoutHash + sep + "token=" + encodeURIComponent(websheetToken) + hash;
  }

  function rewriteCarrierPath(value) {
    if (!absolutePathProxyPrefix || typeof value !== "string") return value;
    if (value.charAt(0) !== "/" || value.indexOf("//") === 0) return value;
    if (value.indexOf("/api/websheets/") === 0) return value;
    return appendWebsheetToken(absolutePathProxyPrefix + value);
  }

  function installRequestRewriter() {
    try {
      const originalOpen = window.XMLHttpRequest && window.XMLHttpRequest.prototype && window.XMLHttpRequest.prototype.open;
      if (originalOpen) {
        window.XMLHttpRequest.prototype.open = function(method, url) {
          const args = Array.prototype.slice.call(arguments);
          this.__vohiveMethod = String(method || "GET").toUpperCase();
          this.__vohiveURL = String(url || "");
          args[1] = rewriteCarrierPath(url);
          return originalOpen.apply(this, args);
        };
      }
      const originalSend = window.XMLHttpRequest && window.XMLHttpRequest.prototype && window.XMLHttpRequest.prototype.send;
      if (originalSend) {
        window.XMLHttpRequest.prototype.send = function() {
          try {
            this.addEventListener("load", function() {
              inspectATTAddressResponse(this.__vohiveMethod || "GET", this.__vohiveURL || "", this.responseText || "");
            });
          } catch (_) {}
          return originalSend.apply(this, arguments);
        };
      }
    } catch (_) {}

    try {
      const originalFetch = window.fetch;
      if (originalFetch) {
        window.fetch = function(input, init) {
          const originalInput = input;
          const method = fetchMethod(input, init);
          const originalURL = fetchURL(input);
          if (typeof input === "string") {
            input = rewriteCarrierPath(input);
          }
          return originalFetch.call(this, input, init).then(function(response) {
            try {
              response.clone().text().then(function(text) {
                inspectATTAddressResponse(method, originalURL || fetchURL(originalInput), text);
              }).catch(function(){});
            } catch (_) {}
            return response;
          });
        };
      }
    } catch (_) {}
  }

  installRequestRewriter();

  function fetchMethod(input, init) {
    if (init && init.method) return String(init.method).toUpperCase();
    if (input && typeof input === "object" && input.method) return String(input.method).toUpperCase();
    return "GET";
  }

  function fetchURL(input) {
    if (typeof input === "string") return input;
    if (input && typeof input === "object" && input.url) return String(input.url || "");
    return "";
  }

  function inspectATTAddressResponse(method, url, text) {
    if (attAddressCompletionPosted || method === "GET" || typeof text !== "string" || text === "") return;
    if (typeof url === "string" && url && url.indexOf("/sfservice/v1/address/e911/") < 0) return;
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      return;
    }
    const address = data && data.e911Address ? data.e911Address : data;
    const status = String(address && address.status ? address.status : "").toLowerCase();
    if (status === "validated") {
      attAddressCompletionPosted = true;
      post({source:"vowifi", controller:"ATTDashboard", method:"e911AddressValidated", event:"entitlementChanged", resultCode:"success"});
    }
  }

  function shellMessage(payload) {
    return {type:"vohive-websheet-callback", token:websheetToken || "", callback: payload};
  }

  function notifyShell(payload) {
    const message = shellMessage(payload);
    try {
      window.parent.postMessage(message, "*");
    } catch (_) {}
    try {
      if (window.top && window.top !== window.parent) {
        window.top.postMessage(message, "*");
      }
    } catch (_) {}
    try {
      const channel = new BroadcastChannel(shellBroadcastName);
      channel.postMessage(message);
      channel.close();
    } catch (_) {}
    try {
      window.localStorage.setItem(shellStorageKey, JSON.stringify({
        type: message.type,
        token: message.token,
        callback: message.callback,
        nonce: String(Date.now())
      }));
    } catch (_) {}
  }

  function post(payload) {
    if (!payload.at) payload.at = new Date().toISOString();
    payload.href = window.location && window.location.href ? window.location.href : "";
    if (payload.source === "odsa") {
      appendStorage(odsaStorageKey, payload);
      try {
        window.dispatchEvent(new CustomEvent("ts43-odsa-callback", {detail: payload}));
      } catch (_) {}
    }
    if (payload.source === "vowifi") {
      appendStorage(vowifiStorageKey, payload);
      try {
        window.dispatchEvent(new CustomEvent("vowifi-callback", {detail: payload}));
      } catch (_) {}
    }
    notifyShell(payload);
    try {
      fetch(callbackURL, {method: "POST", mode: "no-cors", headers: {"Content-Type": "text/plain;charset=UTF-8"}, body: JSON.stringify(payload), credentials: "omit"})
        .catch(function(){});
    } catch (_) {
    }
  }

  function appendStorage(key, payload) {
    try {
      const existing = JSON.parse(window.localStorage.getItem(key) || "[]");
      existing.push(payload);
      window.localStorage.setItem(key, JSON.stringify(existing.slice(-20)));
    } catch (_) {}
  }

  function storedCallbacks(key) {
    try {
      return JSON.parse(window.localStorage.getItem(key) || "[]");
    } catch (_) {
      return [];
    }
  }

  const flow = window.ODSAServiceFlow || {};
  flow.profileReadyWithActivationCode = function(activationCode, iccid, imei) { post({source:"odsa", controller:"ODSAServiceFlow", method:"profileReadyWithActivationCode", event:"profileReadyWithActivationCode", activationCode: activationCode || "", iccid: iccid || "", imei: imei || ""}); };
  flow.profileReadyWithDefaultSmdp = function(defaultSmdpAddress, iccid, imei) { post({source:"odsa", controller:"ODSAServiceFlow", method:"profileReadyWithDefaultSmdp", event:"profileReadyWithDefaultSmdp", defaultSmdpAddress: defaultSmdpAddress || "", iccid: iccid || "", imei: imei || ""}); };
  flow.profileReadyWithDefaultSMDP = flow.profileReadyWithDefaultSmdp;
  flow.selectionCompleted = function(iccid, imei) { post({source:"odsa", controller:"ODSAServiceFlow", method:"selectionCompleted", event:"selectionCompleted", iccid: iccid || "", imei: imei || ""}); };
  flow.finishFlow = function(nextAction) { post({source:"odsa", controller:"ODSAServiceFlow", method:"finishFlow", event:"finishFlow", nextAction: nextAction || ""}); };
  flow.dismissFlow = function() { post({source:"odsa", controller:"ODSAServiceFlow", method:"dismissFlow", event:"dismissFlow"}); };
  flow.deleteToken = function() { post({source:"odsa", controller:"ODSAServiceFlow", method:"deleteToken", event:"deleteToken"}); };
  flow.checkProfileServiceStatus = function() { post({source:"odsa", controller:"ODSAServiceFlow", method:"checkProfileServiceStatus", event:"checkProfileServiceStatus"}); };
  flow.deleteProfileInUse = function(iccid) { post({source:"odsa", controller:"ODSAServiceFlow", method:"deleteProfileInUse", event:"deleteProfileInUse", iccid: iccid || ""}); };
  window.ODSAServiceFlow = flow;
  window.ts43ODSAServiceFlow = Object.freeze({
    callbacks: function() {
      return storedCallbacks(odsaStorageKey);
    }
  });

  function vowifiEvent(method) {
    switch (method) {
    case "entitlementChanged":
      return "entitlementChanged";
    case "dismissFlow":
    case "cancelButtonClicked":
    case "CloseWebView":
    case "closeWebView":
    case "onCloseWebView":
      return "dismissFlow";
    default:
      return method;
    }
  }

  function vowifiResult(event) {
    switch (event) {
    case "entitlementChanged":
      return "success";
    case "dismissFlow":
      return "cancel";
    default:
      return "";
    }
  }

  function vowifiMethod(controller, method) {
    return function() {
      let event = vowifiEvent(method);
      const args = Array.prototype.slice.call(arguments);
      if (method === "phoneServicesAccountStatusChanged" && args[0] === true) {
        event = "entitlementChanged";
      }
      const payload = {
        source: "vowifi",
        controller: controller,
        method: method,
        event: event,
        args: args
      };
      const resultCode = vowifiResult(event);
      if (resultCode) payload.resultCode = resultCode;
      post(payload);
    };
  }

  function installVowifiController(name, methods) {
    const target = window[name] || {};
    for (let i = 0; i < methods.length; i++) {
      const method = methods[i];
      if (typeof target[method] !== "function") {
        target[method] = vowifiMethod(name, method);
      }
    }
    window[name] = target;
    return target;
  }

  const voWiFiWebServiceFlow = installVowifiController("VoWiFiWebServiceFlow", ["entitlementChanged", "dismissFlow"]);
  const wifiCallingWebViewController = installVowifiController("WiFiCallingWebViewController", ["cancelButtonClicked", "cancelButtonPressed", "phoneServicesAccountStatusChanged", "CloseWebView", "closeWebView", "onCloseWebView"]);
  const nsdsWebSheetController = installVowifiController("NsdsWebSheetController", ["entitlementChanged", "dismissFlow", "cancelButtonClicked", "cancelButtonPressed", "phoneServicesAccountStatusChanged", "CloseWebView", "closeWebView", "onCloseWebView"]);
  window.vowifiCallback = Object.freeze({
    done: voWiFiWebServiceFlow.entitlementChanged,
    dismiss: voWiFiWebServiceFlow.dismissFlow,
    controllers: Object.freeze({
      VoWiFiWebServiceFlow: voWiFiWebServiceFlow,
      WiFiCallingWebViewController: wifiCallingWebViewController,
      NsdsWebSheetController: nsdsWebSheetController
    }),
    callbacks: function() {
      return storedCallbacks(vowifiStorageKey);
    }
  });
})();
