local llm = require "llm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects and fingerprints LLM inference APIs exposed over HTTP(S).

Probes a target for the common self-hosted and cloud inference frameworks by their
read-only model-list and metadata endpoints: the OpenAI-compatible API (vLLM, SGLang,
LiteLLM, LocalAI, LM Studio, text-generation-webui, and similar), Ollama, HuggingFace TGI
and TEI, llama.cpp server, KoboldCpp, Triton/KServe (v2), and TorchServe. It also flags the
common AI web UIs / gateways that front a backend (Open WebUI, LibreChat, NextChat, LobeChat,
Flowise, AnythingLLM), reporting each UI's access posture (open / self-registration / login),
which determines whether the backend model can be used without credentials. On a match it
reports the framework, version, model inventory, authentication posture, and notable
information leaks (e.g. a llama.cpp system prompt exposed via /props, or a served model name
exposed via a Prometheus /metrics endpoint). It augments service/version detection via -sV.

By default the script also sends a single minimal "hello" completion request
(max_tokens = 1) to confirm the endpoint actually serves inference and to detect formats
with no model-list endpoint, notably Anthropic's Messages API (/v1/messages). Pass
llm.probe=false for strictly read-only detection (model-list / metadata / health endpoints
only, no inference request).

A bearer token (llm.token) or arbitrary header (llm.header, e.g. an API key or session
cookie) may be supplied to test an authenticated API. Shared logic lives in the llm nselib.
]]

---
-- @usage nmap -p 11434,8000,1234 --script llm-info <target>
-- @usage nmap -sV --script llm-info <target>
-- @usage nmap --script llm-info --script-args llm.token=sk-... <target>
-- @usage nmap --script llm-info --script-args 'llm.header=x-api-key: sk-...' <target>
--
-- @args llm.token   Bearer token, sent as "Authorization: Bearer <token>".
-- @args llm.header  Arbitrary auth header "Name: value" (e.g. "x-api-key: sk-...",
--                   "api-key: ...", "Cookie: session=..."), to test credentialed APIs.
-- @args llm.probe   Send a minimal "hello" inference request to confirm the API and detect
--                   list-less formats (Anthropic). Default true; set false for read-only.
-- @args llm.timeout HTTP timeout in ms (default 7000).
-- @args llm.ua      User-Agent to send (default a neutral browser UA).
-- @args llm.allports Probe every open TCP port (ignore the port heuristic).
--
-- @output
-- PORT      STATE SERVICE
-- 11434/tcp open  llm-api
-- | llm-info:
-- |   framework: Ollama
-- |   version: 0.3.14
-- |   endpoint: /api/tags
-- |   auth: NONE (unauthenticated)
-- |   inference: confirmed (responded to a minimal hello)
-- |   models (3): llama3:8b, qwen2.5:7b, nomic-embed-text:latest
-- |_  SECURITY: unauthenticated inference API (Ollama) exposes 3 model(s); open to compute/cost abuse and model disclosure
--
-- @xmloutput
-- <elem key="framework">Ollama</elem>
-- <elem key="version">0.3.14</elem>
-- <elem key="endpoint">/api/tags</elem>
-- <elem key="auth">NONE (unauthenticated)</elem>
-- <elem key="inference">confirmed (responded to a minimal hello)</elem>
-- <table key="models (3)">
--   <elem>llama3:8b</elem>
--   <elem>qwen2.5:7b</elem>
--   <elem>nomic-embed-text:latest</elem>
-- </table>
-- <elem key="SECURITY">unauthenticated inference API (Ollama) exposes 3 model(s); open to compute/cost abuse and model disclosure</elem>

author = "Ben Williams <ben.williams@nccgroup.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = llm.portrule

action = function(host, port)
  local opts = llm.args()
  local r = llm.detect(host, port, opts)
  if not r then
    return nil
  end

  local out = stdnse.output_table()
  out.framework = r.framework
  if r.ui then out.kind = "web UI (fronts a backend inference server)" end
  if r.version then out.version = r.version end
  if r.server then out.server = r.server end
  out.endpoint = r.endpoint

  if r.ui then
    -- For a web UI the access posture (whether the backend can be used without credentials)
    -- is the relevant state, not a key/token challenge.
    local A = {
      open = "open (no authentication required)",
      onboarding = "no admin account yet (first visitor can claim admin)",
      ["self-registration"] = "self-registration enabled (anyone can sign up)",
      login = "login required",
      unknown = "unknown (not exposed in config)",
    }
    out.access = A[r.access] or r.access or "unknown"
  elseif r.auth_required then
    out.auth = opts.credentialed and "REQUIRED (supplied credential rejected)"
      or "REQUIRED (key/credentials)"
  elseif opts.credentialed then
    out.auth = "PROVIDED (credential accepted)"
  else
    out.auth = "NONE (unauthenticated)"
  end

  if r.inference then out.inference = "confirmed (responded to a minimal hello)" end
  if r.error_sig then out.error_sig = r.error_sig end

  if r.models and #r.models > 0 then
    local label = "models (" .. #r.models .. ")"
    if r.models_enumerated then label = label .. " [enumerated by probing known IDs]" end
    out[label] = r.models
  end
  if r.leaks and #r.leaks > 0 then
    out.leaks = r.leaks
  end

  if r.ui then
    -- The UI finding is driven by the access posture: open and self-registration both grant
    -- unauthenticated use of the backend model; login-gated UIs are reported without a finding.
    if r.access == "open" then
      out.SECURITY = string.format(
        "unauthenticated LLM web UI (%s) grants open access to a backend inference server%s",
        r.framework, r.gateway and "; prediction endpoints may be publicly callable" or "")
    elseif r.access == "onboarding" then
      out.SECURITY = string.format(
        "unconfigured LLM web UI (%s) has no admin account yet; the first visitor can claim admin and use the backend inference server",
        r.framework)
    elseif r.access == "self-registration" then
      out.SECURITY = string.format(
        "LLM web UI (%s) allows self-registration for unauthenticated access to a backend inference server",
        r.framework)
    elseif r.access == "unknown" then
      out.SECURITY = string.format(
        "exposed LLM web UI (%s) fronting a backend inference server%s; verify whether unauthenticated use is permitted",
        r.framework, r.gateway and " (prediction endpoints may be publicly callable)" or "")
    end
  elseif not r.auth_required and not opts.credentialed then
    local n = (r.models and #r.models) or 0
    out.SECURITY = string.format(
      "unauthenticated inference API (%s) exposes %d model(s); open to compute/cost abuse and model disclosure",
      r.framework, n)
  end

  -- Feed -sV.
  port.version.name = r.ui and "llm-ui" or "llm-api"
  port.version.product = r.framework
  if r.version then port.version.version = r.version end
  port.version.extrainfo = r.auth_required and "auth required" or "unauthenticated"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
