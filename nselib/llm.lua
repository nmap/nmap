---
-- Shared library for fingerprinting LLM inference APIs exposed over HTTP(S).
--
-- Detects the common self-hosted and cloud inference frameworks by their read-only
-- model-list and metadata endpoints: the OpenAI-compatible API (vLLM, SGLang, LiteLLM,
-- LocalAI, LM Studio, text-generation-webui, and similar), Ollama, HuggingFace TGI and TEI,
-- llama.cpp server, KoboldCpp, Triton/KServe (v2), and TorchServe. It also flags the
-- common AI web UIs / gateways that front a backend (Open WebUI, LibreChat, NextChat,
-- LobeChat, Flowise, AnythingLLM), reporting each UI's access posture (open /
-- self-registration / login) since that determines whether the backend model can be
-- reached without credentials. Reports the framework, version, model inventory,
-- authentication posture, and notable information leaks (including model names exposed
-- via a Prometheus /metrics endpoint).
--
-- By default the library also sends a single minimal "hello" completion (max_tokens = 1)
-- to confirm an endpoint serves inference and to detect formats with no model-list endpoint
-- (notably the Anthropic Messages API). Set llm.probe=false to keep detection strictly
-- read-only. Authorised testing only.
--
-- @author Ben Williams <ben.williams@nccgroup.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("llm", stdnse.seeall)

-- Neutral default User-Agent (a UA containing "nmap" is blocked by common WAFs).
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

-- Ports commonly hosting inference APIs / UIs (in addition to HTTP-fingerprinted ports).
-- 11434 Ollama, 8000 vLLM/TGI/Triton, 30000 SGLang, 1234 LM Studio, 4000 LiteLLM,
-- 5001 KoboldCpp, 8081 TorchServe mgmt, 7860/5000 gradio web-UIs, 8080/3000 Open WebUI /
-- NextChat, 3080 LibreChat, 3001 AnythingLLM, 3210 LobeChat.
PORTS = { 11434, 8000, 8080, 8081, 1234, 4000, 5000, 5001, 7860, 3000, 3001, 3080, 3210, 8888, 9000, 30000 }
local PORTS_SET = {}
for _, p in ipairs(PORTS) do PORTS_SET[p] = true end

-- Build the options table from script-args, including any supplied credential. A bearer
-- token (llm.token) and/or an arbitrary header (llm.header, e.g. "x-api-key: sk-...",
-- "api-key: ...", "Cookie: session=...") let the scripts test authenticated APIs.
function args()
  local headers = {}
  local token = stdnse.get_script_args("llm.token")
  if token then headers["Authorization"] = "Bearer " .. token end
  local raw = stdnse.get_script_args("llm.header")
  if raw then
    local k, v = tostring(raw):match("^%s*([^:%s]+)%s*:%s*(.+)$")
    if k then headers[k] = v end
  end
  local probe = stdnse.get_script_args("llm.probe")
  return {
    timeout = tonumber(stdnse.get_script_args("llm.timeout")) or 7000,
    ua = stdnse.get_script_args("llm.ua") or DEFAULT_UA,
    headers = headers,
    credentialed = (token ~= nil) or (raw ~= nil),
    -- Active "hello" probe is ON by default; llm.probe=false makes the script read-only.
    probe = not (probe == "false" or probe == "0"),
  }
end

-- Shared portrule: HTTP-fingerprinted ports, the common inference port set, and any
-- service -sV probed but could not identify (inference servers behind uvicorn/ASGI are
-- often not recognised as HTTP). llm.allports forces a probe on every open TCP port.
function portrule(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then return false end
  if stdnse.get_script_args("llm.allports") then return true end
  if shortport.http(host, port) then return true end
  if PORTS_SET[port.number] then return true end
  if port.version and port.version.service_fp then return true end
  return false
end

-- Read-only HTTP GET, carrying any supplied credential. Returns (status, body,
-- header-table) or nil on connection failure.
local function get(host, port, path, opts)
  local h = { ["User-Agent"] = opts.ua }
  if opts.headers then for k, v in pairs(opts.headers) do h[k] = v end end
  local resp = http.get(host, port, path, { header = h, timeout = opts.timeout, no_cache = true })
  if not resp then return nil end
  return resp.status, resp.body, resp.header
end

local function jparse(body)
  if not body or body == "" then return nil end
  local ok, obj = json.parse(body)
  if ok and type(obj) == "table" then return obj end
  return nil
end

--------------------------------------------------------------------------------
-- Framework detectors. Each returns a result table or nil:
--   { framework, endpoint, version, models={}, auth_required=bool, leaks={}, server }
--------------------------------------------------------------------------------

-- Ollama: /api/tags lists installed models; /api/version gives the version; the root
-- path returns the literal banner "Ollama is running".
local function detect_ollama(host, port, opts)
  local st, body = get(host, port, "/api/tags", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and type(doc.models) == "table" then
      local models = {}
      for _, m in ipairs(doc.models) do models[#models + 1] = m.name or m.model or "?" end
      local r = { framework = "Ollama", endpoint = "/api/tags", models = models, auth_required = false, confidence = 90 }
      local _, vb = get(host, port, "/api/version", opts)
      local vd = jparse(vb)
      if vd and vd.version then r.version = vd.version end
      return r
    end
  elseif st == 401 or st == 403 then
    return { framework = "Ollama", endpoint = "/api/tags", auth_required = true, confidence = 90 }
  end
  local st2, body2 = get(host, port, "/", opts)
  if st2 == 200 and body2 and body2:find("Ollama is running", 1, true) then
    return { framework = "Ollama", endpoint = "/", models = {}, auth_required = false, confidence = 80 }
  end
  return nil
end

-- OpenAI-compatible: GET /v1/models returns {"object":"list","data":[{"object":"model"}]}.
-- This catches vLLM, LiteLLM, LocalAI, LM Studio, text-generation-webui, llama.cpp, etc.;
-- secondary probes disambiguate the specific framework.
local function detect_openai(host, port, opts)
  local st, body, hdr = get(host, port, "/v1/models", opts)
  if st == 401 or st == 403 then
    return { framework = "OpenAI-compatible API", endpoint = "/v1/models", auth_required = true, confidence = 30 }
  end
  if st ~= 200 then return nil end
  local doc = jparse(body)
  if not (doc and doc.object == "list" and type(doc.data) == "table") then return nil end
  local models = {}
  for _, m in ipairs(doc.data) do models[#models + 1] = m.id or "?" end
  local r = { framework = "OpenAI-compatible API", endpoint = "/v1/models",
              models = models, auth_required = false, leaks = {}, confidence = 30 }
  if hdr and hdr.server then r.server = hdr.server end

  -- vLLM: GET /version -> {"version": "0.x"}
  local _, vb = get(host, port, "/version", opts)
  local vd = jparse(vb)
  if vd and vd.version then r.framework = "vLLM (OpenAI-compatible)"; r.version = vd.version; r.confidence = 85 end

  -- HuggingFace TGI / TEI: GET /info -> {"model_id": ..., "version": ...}. A model_type of
  -- "embedding" identifies Text Embeddings Inference rather than text generation.
  local _, ib = get(host, port, "/info", opts)
  local idoc = jparse(ib)
  if idoc and idoc.model_id then
    if type(idoc.model_type) == "table" and idoc.model_type.embedding then
      r.framework = "HF text-embeddings-inference"
    else
      r.framework = "HF text-generation-inference"
    end
    r.version = idoc.version or r.version
    if #r.models == 0 then r.models = { idoc.model_id } end
    r.confidence = 85
  end

  -- llama.cpp server: GET /props -> default_generation_settings / model_path / system_prompt
  local _, pb = get(host, port, "/props", opts)
  local pdoc = jparse(pb)
  if pdoc and (pdoc.default_generation_settings or pdoc.model_path or pdoc.system_prompt ~= nil) then
    r.framework = "llama.cpp server"
    r.confidence = 85
    if pdoc.model_path and #r.models == 0 then r.models = { pdoc.model_path } end
    if type(pdoc.system_prompt) == "string" and pdoc.system_prompt ~= "" then
      r.leaks[#r.leaks + 1] = "system prompt disclosed via /props"
    end
  end

  -- SGLang: GET /get_model_info -> {"model_path": ..., "is_generation": ...}
  local _, gb = get(host, port, "/get_model_info", opts)
  local gdoc = jparse(gb)
  if gdoc and gdoc.model_path then
    r.framework = "SGLang (OpenAI-compatible)"
    r.confidence = 85
    if #r.models == 0 then r.models = { gdoc.model_path } end
  end
  return r
end

-- HuggingFace TGI / TEI without an OpenAI shim (older builds): GET /info. A model_type of
-- "embedding" marks the Text Embeddings Inference server rather than text generation.
local function detect_tgi(host, port, opts)
  local st, body = get(host, port, "/info", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and doc.model_id then
      local fw = "HF text-generation-inference"
      if type(doc.model_type) == "table" and doc.model_type.embedding then
        fw = "HF text-embeddings-inference"
      end
      return { framework = fw, endpoint = "/info",
               version = doc.version, models = { doc.model_id }, auth_required = false, confidence = 85 }
    end
  end
  return nil
end

-- KoboldCpp / KoboldAI United: GET /api/extra/version -> {"result":"KoboldCpp","version":...};
-- /api/v1/model names the loaded model. A real KoboldCpp simultaneously emulates the Ollama
-- (/api/tags), OpenAI (/v1/models) and llama.cpp (/props) APIs, so several other detectors
-- also fire on it. The /api/extra/version banner is unambiguous (no other framework serves
-- it), so this is scored above all of them - including Ollama (90) - to keep identification
-- correct and order-independent (confirmed by field-testing a real KoboldCpp 1.115.2).
local function detect_koboldcpp(host, port, opts)
  local st, body = get(host, port, "/api/extra/version", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and type(doc.result) == "string" and doc.result:find("Kobold", 1, true) then
      local r = { framework = "KoboldCpp", endpoint = "/api/extra/version",
                  version = doc.version, models = {}, auth_required = false, confidence = 95 }
      local _, mb = get(host, port, "/api/v1/model", opts)
      local md = jparse(mb)
      if md and type(md.result) == "string" then
        r.models = { (md.result:gsub("^koboldcpp/", "")) }
      end
      return r
    end
  end
  return nil
end

-- llama.cpp server without an OpenAI shim (older builds): GET /props.
local function detect_llamacpp(host, port, opts)
  local st, body = get(host, port, "/props", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and (doc.default_generation_settings or doc.model_path) then
      local r = { framework = "llama.cpp server", endpoint = "/props", auth_required = false, models = {}, leaks = {}, confidence = 85 }
      if doc.model_path then r.models = { doc.model_path } end
      if type(doc.system_prompt) == "string" and doc.system_prompt ~= "" then
        r.leaks[#r.leaks + 1] = "system prompt disclosed via /props"
      end
      return r
    end
  end
  return nil
end

-- NVIDIA Triton / KServe v2 inference protocol: GET /v2 server metadata, /v2/health/ready.
local function detect_triton(host, port, opts)
  local st, body = get(host, port, "/v2", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and doc.name then
      return { framework = "Triton/KServe (v2 inference)", endpoint = "/v2",
               version = doc.version, models = {}, auth_required = false, server = doc.name, confidence = 85 }
    end
  end
  local hs = get(host, port, "/v2/health/ready", opts)
  if hs == 200 then
    return { framework = "KServe/Triton (v2 inference)", endpoint = "/v2/health/ready",
             models = {}, auth_required = false, confidence = 75 }
  end
  return nil
end

-- TorchServe management API: GET /models -> {"models":[{"modelName": ...}]}.
local function detect_torchserve(host, port, opts)
  local st, body = get(host, port, "/models", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and type(doc.models) == "table" and doc.models[1] and doc.models[1].modelName then
      local models = {}
      for _, m in ipairs(doc.models) do models[#models + 1] = m.modelName end
      return { framework = "TorchServe (management API)", endpoint = "/models",
               models = models, auth_required = false, confidence = 75 }
    end
  end
  return nil
end

-- LLM web UIs / gateways. These are front-ends that proxy to a backend inference server
-- rather than serving inference themselves; an exposed instance often grants unauthenticated
-- use of a real backend model. Reported distinctly (ui = true) and never sent an active
-- inference probe. Where the UI publishes its auth posture in a read-only config endpoint,
-- the access state is reported (access = open / self-registration / login / unknown), since
-- that is what determines whether the backend can be reached without credentials:
--   open               no authentication at all - anyone can use the backend model
--   self-registration  signup is open - anyone can create an account and use the backend
--   login              authentication required (access code / account)
--   unknown            UI identified but its auth posture is not exposed in config
local function detect_webui(host, port, opts)
  -- Open WebUI / LibreChat / NextChat all publish a read-only /api/config with auth flags.
  local st, body = get(host, port, "/api/config", opts)
  if st == 200 then
    local doc = jparse(body)
    if doc and doc.name == "Open WebUI" then
      -- features.auth=false means WEBUI_AUTH is disabled (fully open); enable_signup=true
      -- means open self-registration.
      -- features.auth=false means WEBUI_AUTH is disabled (fully open); onboarding=true means
      -- no admin account exists yet, so the first visitor can claim admin; enable_signup=true
      -- means open self-registration.
      local f = type(doc.features) == "table" and doc.features or {}
      local r = { framework = "Open WebUI", endpoint = "/api/config", ui = true,
                  version = doc.version, models = {}, confidence = 90 }
      if f.auth == false then
        r.access = "open"; r.auth_required = false
      elseif doc.onboarding == true then
        r.access = "onboarding"; r.auth_required = false
      elseif f.enable_signup == true then
        r.access = "self-registration"; r.auth_required = false
      else
        r.access = "login"; r.auth_required = true
      end
      return r
    end
    if doc and (doc.appTitle or doc.registrationEnabled ~= nil or doc.emailLoginEnabled ~= nil
        or doc.socialLogins) then
      local r = { framework = "LibreChat", endpoint = "/api/config", ui = true,
                  models = {}, confidence = 88 }
      if doc.registrationEnabled == true then
        r.access = "self-registration"; r.auth_required = false
      else
        r.access = "login"; r.auth_required = true
      end
      return r
    end
    -- NextChat / ChatGPT-Next-Web: /api/config -> {"needCode":bool,"hideUserApiKey":...}.
    -- needCode=false means no access code is required: anyone can use the owner's backend.
    if doc and doc.needCode ~= nil then
      local r = { framework = "NextChat", endpoint = "/api/config",
                  ui = true, models = {}, confidence = 85 }
      if doc.needCode == false then
        r.access = "open"; r.auth_required = false
      else
        r.access = "login"; r.auth_required = true
      end
      return r
    end
  end
  -- LobeChat: GET /manifest.json (or .webmanifest) -> {"name":"LobeChat",...}. Auth posture
  -- (an optional access code) is not exposed in config, so report access as unknown.
  for _, mpath in ipairs({ "/manifest.json", "/manifest.webmanifest" }) do
    local ms, mb = get(host, port, mpath, opts)
    if ms == 200 then
      local md = jparse(mb)
      if md and type(md.name) == "string" and md.name:find("LobeChat", 1, true) then
        return { framework = "LobeChat", endpoint = mpath, ui = true, models = {},
                 auth_required = false, access = "unknown", confidence = 82 }
      end
    end
  end
  -- Flowise (LangChain flow builder / gateway): GET /api/v1/version -> {"version":...}.
  -- Its chatflow prediction endpoints are often publicly callable, so flag it as a gateway.
  local fs, fb = get(host, port, "/api/v1/version", opts)
  if fs == 200 then
    local fd = jparse(fb)
    if fd and fd.version then
      return { framework = "Flowise", endpoint = "/api/v1/version", ui = true, gateway = true,
               version = fd.version, models = {}, auth_required = false, access = "unknown", confidence = 82 }
    end
  end
  -- AnythingLLM: GET /api/ping -> {"online":true}; the served SPA confirms it.
  local ps = get(host, port, "/api/ping", opts)
  if ps == 200 then
    local _, hb = get(host, port, "/", opts)
    if hb and hb:find("AnythingLLM", 1, true) then
      return { framework = "AnythingLLM", endpoint = "/api/ping", ui = true, models = {},
               auth_required = false, access = "unknown", confidence = 80 }
    end
  end
  return nil
end

local DETECTORS = {
  detect_ollama, detect_openai, detect_tgi, detect_llamacpp, detect_koboldcpp,
  detect_triton, detect_torchserve, detect_webui,
}

--------------------------------------------------------------------------------
-- Active "hello" probe (on by default). Sends a single minimal completion request and
-- looks for an inference-shaped response: it confirms the endpoint actually serves a model
-- (not just lists them) and detects formats with no list endpoint, notably
-- Anthropic's Messages API. Kept minimal (max_tokens = 1, prompt "hello").
--------------------------------------------------------------------------------

local function gen(obj)
  local ok, s = pcall(json.generate, obj)
  return ok and s or nil
end

local function post(host, port, path, extra, body, opts)
  local h = { ["User-Agent"] = opts.ua, ["Content-Type"] = "application/json" }
  if opts.headers then for k, v in pairs(opts.headers) do h[k] = v end end
  if extra then for k, v in pairs(extra) do h[k] = v end end
  local resp = http.post(host, port, path, { header = h, timeout = opts.timeout }, nil, body)
  if not resp then return nil end
  return resp.status, resp.body
end

-- OpenAI-compatible chat hello. Returns "confirmed" on a completion or an OpenAI-shaped
-- error (either proves a chat inference endpoint), "auth" on a credential challenge.
local function hello_openai(host, port, model, opts)
  local body = gen({ model = model or "gpt-3.5-turbo",
                     messages = { { role = "user", content = "hello" } }, max_tokens = 1 })
  if not body then return nil end
  local st, rb = post(host, port, "/v1/chat/completions", nil, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if st == 200 and doc and (doc.choices or doc.object == "chat.completion") then return "confirmed" end
  if st == 401 or st == 403 then return "auth" end
  if doc and type(doc.error) == "table" then return "confirmed" end
  return nil
end

-- Ollama native generate hello.
local function hello_ollama(host, port, model, opts)
  local body = gen({ model = model or "llama3", prompt = "hello", stream = false,
                     options = { num_predict = 1 } })
  if not body then return nil end
  local st, rb = post(host, port, "/api/generate", nil, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if st == 200 and doc and (doc.response ~= nil or doc.done ~= nil) then return "confirmed" end
  if doc and doc.error then return "confirmed" end
  return nil
end

-- Anthropic Messages API: no list endpoint exists, so a minimal /v1/messages request is the
-- only fingerprint. Identified by the Anthropic message/error response shape; an
-- unauthenticated server returns 401 WITHOUT running a model.
local function probe_anthropic(host, port, opts)
  local body = gen({ model = "claude-3-5-haiku-latest", max_tokens = 1,
                     messages = { { role = "user", content = "hello" } } })
  if not body then return nil end
  local st, rb = post(host, port, "/v1/messages", { ["anthropic-version"] = "2023-06-01" }, body, opts)
  if not st then return nil end
  local doc = jparse(rb)
  if doc and (doc.type == "message"
      or (doc.type == "error" and type(doc.error) == "table" and doc.error.type)) then
    return { framework = "Anthropic Messages API", endpoint = "/v1/messages",
             models = {}, auth_required = (st == 401 or st == 403), confidence = 88,
             inference = (st == 200) and "confirmed" or nil }
  end
  return nil
end

-- Known model IDs to probe on an API with no usable list endpoint (Anthropic) or one that
-- is disabled. A small built-in set; a model that responds (rather than "model not found")
-- is reported as present/accessible. Active and bounded - authorised assessments only.
KNOWN_MODELS = {
  anthropic = { "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest",
                "claude-3-opus-latest", "claude-3-haiku-20240307" },
  openai = { "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo" },
}

local function enum_anthropic(host, port, opts)
  local found = {}
  for _, m in ipairs(KNOWN_MODELS.anthropic) do
    local body = gen({ model = m, max_tokens = 1, messages = { { role = "user", content = "hi" } } })
    local st, rb = post(host, port, "/v1/messages", { ["anthropic-version"] = "2023-06-01" }, body, opts)
    local doc = jparse(rb)
    if st == 200 then
      found[#found + 1] = m
    elseif doc and doc.type == "error" and type(doc.error) == "table"
        and doc.error.type ~= "not_found_error" and st ~= 404 then
      found[#found + 1] = m .. " (accessible; non-404 response)"
    end
  end
  return found
end

local function enum_openai(host, port, opts)
  local found = {}
  for _, m in ipairs(KNOWN_MODELS.openai) do
    local body = gen({ model = m, messages = { { role = "user", content = "hi" } }, max_tokens = 1 })
    local st = post(host, port, "/v1/chat/completions", nil, body, opts)
    if st == 200 then found[#found + 1] = m end
  end
  return found
end

-- Error-condition fingerprint: requesting a bogus model returns a model-not-found error
-- WITHOUT running inference, and the body shape distinguishes frameworks/stacks:
--   {"object":"error", "type":"NotFoundError"}      -> vLLM
--   {"detail": ...}                                 -> FastAPI/Starlette-based server
--   {"error":{"type":"invalid_request_error",...}}  -> canonical OpenAI format
-- Returns { framework?, error_sig } or nil.
local function refine_by_error(host, port, opts)
  local body = gen({ model = "__nmap_probe_404__",
                     messages = { { role = "user", content = "x" } }, max_tokens = 1 })
  if not body then return nil end
  local _, rb = post(host, port, "/v1/chat/completions", nil, body, opts)
  local doc = jparse(rb)
  if not doc then return nil end
  if doc.object == "error" then
    return { framework = "vLLM (OpenAI-compatible)", error_sig = "{object:error} type=" .. tostring(doc.type) }
  elseif doc.detail ~= nil then
    return { error_sig = "{detail} (FastAPI/Starlette)" }
  elseif type(doc.error) == "table" then
    return { error_sig = "{error} " .. tostring(doc.error.code or doc.error.type) }
  end
  return nil
end

-- Prometheus /metrics, exposed by several frameworks (vLLM, TGI, SGLang), frequently leaks the
-- served model name in a metric label and confirms the framework from the metric-name prefix.
-- Read-only GET. Returns { models={}, framework? } or nil.
local function scan_metrics(host, port, opts)
  local st, body = get(host, port, "/metrics", opts)
  if st ~= 200 or not body or body == "" then return nil end
  if not (body:find("model_name=", 1, true) or body:find("# TYPE", 1, true)) then return nil end
  local out = { models = {} }
  local seen = {}
  for m in body:gmatch('model_name="([^"]+)"') do
    if not seen[m] then seen[m] = true; out.models[#out.models + 1] = m end
  end
  if body:find("vllm:", 1, true) then out.framework = "vLLM (OpenAI-compatible)"
  elseif body:find("sglang:", 1, true) then out.framework = "SGLang (OpenAI-compatible)"
  elseif body:find("tgi_", 1, true) then out.framework = "HF text-generation-inference" end
  return out
end

-- Probe a host:port for a known inference API. Every detector runs; the result is chosen by
-- signal specificity (the `confidence` each detector assigns), not by detector order, so a
-- server matching several signatures (e.g. Ollama, which also serves /v1/models) is reported
-- by its most specific match. A positive (HTTP 200) identification always beats an auth-gated
-- hint (a framework endpoint returning 401/403). Reordering DETECTORS cannot change the result.
function detect(host, port, opts)
  opts = opts or args()
  local best_pos, best_gated
  for _, d in ipairs(DETECTORS) do
    local r = d(host, port, opts)
    if r then
      r.confidence = r.confidence or 0
      if r.auth_required then
        if not best_gated or r.confidence > best_gated.confidence then best_gated = r end
      else
        if not best_pos or r.confidence > best_pos.confidence then best_pos = r end
      end
    end
  end
  local result = best_pos or best_gated

  -- Active "hello" probe (on by default): confirm inference on an identified endpoint, or
  -- actively detect a list-less API (Anthropic) / otherwise-unidentified inference endpoint.
  -- Never probe a web UI / gateway: it is a front-end, not an inference endpoint.
  if opts.probe and not (result and result.ui) then
    if result and not result.auth_required then
      -- Confirm inference with a hello only when it adds information. Skip it for a framework
      -- that already lists its models: the list already proves a live inference endpoint, and
      -- a hello would force a slow on-demand model load (e.g. seconds on Ollama) for no new
      -- signal. A generic OpenAI match, or a server with no listed models, still gets the hello.
      local listed = result.models and #result.models > 0
      if result.framework == "OpenAI-compatible API" or not listed then
        local conf
        if result.framework == "Ollama" then
          conf = hello_ollama(host, port, result.models and result.models[1], opts)
        else
          conf = hello_openai(host, port, result.models and result.models[1], opts)
        end
        if conf then result.inference = conf end
      end
      -- Error-condition fingerprint: refine a generic OpenAI match and record an error sig.
      if result.endpoint == "/v1/models" or result.endpoint == "/v1/chat/completions" then
        local ref = refine_by_error(host, port, opts)
        if ref then
          if ref.framework and result.framework == "OpenAI-compatible API" then
            result.framework = ref.framework
            result.confidence = 60
          end
          if ref.error_sig then result.error_sig = ref.error_sig end
        end
      end
    elseif not result then
      result = probe_anthropic(host, port, opts)
      if not result and hello_openai(host, port, nil, opts) then
        result = { framework = "OpenAI-compatible API", endpoint = "/v1/chat/completions",
                   models = {}, auth_required = false, confidence = 40, inference = "confirmed" }
      end
    end

    -- Active model enumeration for an API with no usable list (Anthropic) or a disabled one:
    -- probe a small set of known model IDs and report those that respond.
    if result and not result.auth_required and (not result.models or #result.models == 0) then
      local found
      if result.framework:find("Anthropic", 1, true) then
        found = enum_anthropic(host, port, opts)
      elseif result.framework:find("OpenAI", 1, true) or result.endpoint == "/v1/chat/completions" then
        found = enum_openai(host, port, opts)
      end
      if found and #found > 0 then result.models = found; result.models_enumerated = true end
    end
  end

  -- Prometheus metrics leak (read-only): for OpenAI-family servers, /metrics often exposes the
  -- served model name and confirms the framework. Recorded as a leak and a model source.
  if result and not result.auth_required and result.framework
      and (result.framework:find("OpenAI", 1, true) or result.framework:find("vLLM", 1, true)
           or result.framework:find("SGLang", 1, true) or result.framework:find("text-generation", 1, true)) then
    local m = scan_metrics(host, port, opts)
    if m then
      if m.framework and result.framework == "OpenAI-compatible API" then
        result.framework = m.framework
        if (result.confidence or 0) < 60 then result.confidence = 60 end
      end
      if #m.models > 0 then
        result.leaks = result.leaks or {}
        result.leaks[#result.leaks + 1] = "model name disclosed via /metrics"
        if not result.models or #result.models == 0 then result.models = m.models end
      end
    end
  end

  -- Capture the Server response header of the matched endpoint as a secondary fingerprint
  -- (uvicorn, TornadoServer, ...); it sometimes carries a version the API itself does not.
  if result and not result.server then
    local _, _, h = get(host, port, result.endpoint, opts)
    if h and h["server"] then result.server = h["server"] end
  end
  return result
end

return _ENV
