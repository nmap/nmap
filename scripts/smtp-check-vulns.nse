description = [[
Checks for SMTP, SMTPS and Submission vulnerabilities:

* Memory corruption in Postfix SMTP server Cyrus SASL support
  (CVE-2011-1720)
  http://www.postfix.org/CVE-2011-1720.html
]]

---
-- @usage
-- nmap --script=smtp-check-vulns --script-args='smtp.domain=<domain>' -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 25/tcp open  smtp
-- | smtp-check-vulns:
-- | Postfix Cyrus SASL (CVE-2011-1720):
-- |   AUTH MECHANISMS: CRAM-MD5 DIGEST-MD5 NTLM PLAIN LOGIN
-- |   AUTH tests: CRAM-MD5
-- |_  Postfix Cyrus SASL authentication: VULNERABLE (CRAM-MD5 => DIGEST-MD5)
--
-- @args
-- smtp.domain Define the domain to be used in the SMTP EHLO command.

author = "Djalal Harouni"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

require "shortport"
require "stdnse"

portrule = shortport.port_or_service({25, 465, 587},
                {"smtp", "smtps", "submission"})

local ERROR_MESSAGES = {
  ["EOF"] = "connection closed",
  ["TIMEOUT"] = "connection timeout",
  ["ERROR"] = "failed to receive data"
}

local SMTP_CMD = {
  ["EHLO"] = {
    cmd = "EHLO",
    success = {
      [250] = "Requested mail action okay, completed",
    },
    errors = {
      [421] = "<domain> Service not available, closing transmission channel",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [504] = "Command parameter not implemented",
      [550] = "Not implemented",
    },
  },
  ["AUTH"] = {
    cmd = "AUTH",
    success = {[334] = ""},
    errors = {
      [501] = "Authentication aborted",
    }
  },
  ["STARTTLS"] = {
    cmd = "STARTTLS",
    success = {
      [220] = "Ready to start TLS"
    },
    errors = {
      [501] = "Syntax error (no parameters allowed)",
      [454] = "TLS not available due to temporary reason",
    }
  }
}


-- Get a domain to be used in the SMTP commands that need it. If the
-- user specified one through a script argument this function will return
-- it. Otherwise it will try to find the domain from the typed hostname
-- and from the rDNS name. If it still can't find one it will use the
-- nmap.scanme.org by default.
--
-- @param host Current scanned host
-- @return The hostname to be used
function get_domain(host)
  local nmap_domain = "nmap.scanme.org"

  -- Use the user provided options.
  local result = stdnse.get_script_args("smtp.domain") or
                    stdnse.get_script_args("smtp-check-vulns.domain")

  if not result then
    if type(host) == "table" then
      if host.targetname then
        result = host.targetname
      elseif (host.name ~= "" and host.name) then
        result = host.name
      end
    end
  end

  return result or nmap_domain
end

local function smtp_finish(socket, status, msg)
  if socket then
    socket:send("QUIT\r\n")
    socket:close()
  end
  return status, msg
end

function smtp_send(socket, request)
  local status, response = socket:send(request)
  if not status then
    return status, string.format("failed to send request: %s",
                      request)
  end

  return true, response
end

function smtp_request(socket, cmd, data)
  local packet = cmd
  if data then
    packet = cmd.." "..data
  end
  local status, ret = smtp_send(socket, packet)
  if not status then
    return smtp_finish(nil, status, ret)
  end

  status, ret = socket:receive_lines(1)
  if not status then
    return smtp_finish(nil, status,
              (ERROR_MESSAGES[ret] or "unspecified error"))
  end

  return status, ret
end

function check_smtp_reply(cmd, response)
  local code, msg = string.match(response, "^([0-9]+)%s*")
  if code then
    code = tonumber(code)
    if SMTP_CMD[cmd] and SMTP_CMD[cmd].success[code] then
      return true, SMTP_CMD[cmd].success[code]
    end
  end
  return false, string.format("%s failed: %s", cmd, response)
end

-- Checks if the SMTP server is vulnerable to CVE-2011-1720
-- Postfix Cyrus SASL authentication memory corruption
-- http://www.postfix.org/CVE-2011-1720.html
function check_cve_2011_1720(smtp)
  local postfix_vuln = "Postfix Cyrus SASL authentication"

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
 
  local socket = nmap.new_socket()
  local status, ret = socket:connect(smtp.host, smtp.port, "tcp")

  if not status then
    return false, "Couldn't connect to remote host"
  end

  local i, response = 0, nil
  -- just a small loop
  repeat
    status, response = socket:receive_lines(1)
    i = i + 1
  until response or i == 3

  if not status then
    return smtp_finish(nil, status,
              (ERROR_MESSAGES[response] or "unspecified error"))
  end

  status, response = smtp_request(socket, "EHLO",
                        string.format("%s\r\n",smtp.domain))
  if not status then
    return status, response
  end

  status, ret = check_smtp_reply("EHLO", response)
  if not status then
    return smtp_finish(socket, status, ret)
  end

  local starttls = false
  local function chk_starttls(line)
    return line:match("STARTTLS")
  end

  local auth_mech_list, auth_mech_str, chk_vuln = {}, "", false
  -- parse and check the authentication mechanisms
  local function chk_auth_mechanisms(line)
    local authstr = line:match("%d+\-AUTH%s(.*)$")
    if authstr then
      auth_mech_str = authstr
      for mech in authstr:gmatch("[^%s]+") do
        if AUTH_VULN[mech] then
          auth_mech_list[mech] = mech
          if not chk_vuln then
            chk_vuln = true
          end
        end
      end
    end
  end

  -- parse server response
  for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
    if not next(auth_mech_list) then
      chk_auth_mechanisms(line)
    end

    if not starttls then
      starttls = chk_starttls(line)
    end
  end

  -- fallback to STARTTLS to get the auth mechanisms
  if not next(auth_mech_list) and smtp.port.number ~= 25 and
    starttls then
    status, response = smtp_request(socket,"STARTTLS\r\n")
    if not status then
      return status, response
    end
    
    status, ret = check_smtp_reply("STARTTLS", response)
    if not status then
      return smtp_finish(socket, status, ret)
    end

    status, ret = socket:reconnect_ssl()
    if not status then
      return smtp_finish(nil, status, ret)
    end
  
    status, response = smtp_request(socket, "EHLO",
                        string.format("%s\r\n",smtp.domain))
    if not status then
      return status, response
    end

    status, ret = check_smtp_reply("EHLO", response)
    if not status then
      return smtp_finish(socket, status, ret)
    end

    for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
      if not next(auth_mech_list) then
        chk_auth_mechanisms(line)
      end
    end
  end

  local output = {}
  output.name = "Postfix Cyrus SASL (CVE-2011-1720):"
  if (#auth_mech_str > 0) then
    table.insert(output, string.format("AUTH MECHANISMS: %s", auth_mech_str))

    -- maybe vulnerable
    if next(auth_mech_list) and chk_vuln then

      -- Kill the Postfix smtpd
      -- Returns true, true if the smtpd was killed
      local function kill_smtpd(socket, mech, mkill)
        local killed = false
        status, response = smtp_request(socket, "AUTH",
                          string.format("%s\r\n", mech))
        if not status then
          return status, ret
        end

        status, ret = check_smtp_reply("AUTH", response)
        if not status then
          return smtp_finish(socket, status, ret)
        end

        -- abort authentication
        smtp_request(socket, "*\r\n")

        status, response = smtp_request(socket, "AUTH",
                          string.format("%s\r\n", mkill))
        if not status then
          if response ~= ERROR_MESSAGES["EOF"] then
            return status, ret
          else
            killed = true
          end
        else
          -- if not killed then abort the last authentication
          smtp_request(socket, "*\r\n")
        end
        return true, killed
      end

      local auth_tests = ""
      for mech in pairs(auth_mech_list) do
        for mkill in pairs(AUTH_VULN[mech].killby) do

          if auth_mech_list[mkill] then
            auth_tests = auth_tests.." "..mech

            local probe = AUTH_VULN[mech].killby[mkill].probe

            for p = 1, probe do
              status, ret = kill_smtpd(socket, mech, mkill)
              if not status then
                return smtp_finish(nil, status, ret)
              end

              if ret then
                table.insert(output,
                    string.format("AUTH tests:%s", auth_tests))
                table.insert(output,
                    string.format("%s: VULNERABLE (%s => %s)",
                        postfix_vuln, mech, mkill))
                return smtp_finish(nil, true, output)
              end

            end

          end

        end
      end

      table.insert(output, string.format("AUTH tests:%s", auth_tests))
    end 
  else
    table.insert(output, "Authentication is not available")
  end
   
  table.insert(output, string.format("%s: NOT VULNERABLE", postfix_vuln))
  return smtp_finish(socket, true, output)
end

action = function(host, port)
  local smtp_opts = { host = host, port = port }
  smtp_opts.domain = get_domain(host)
  local status, output = check_cve_2011_1720(smtp_opts)
  if not status then
    stdnse.print_debug(1, "%s: %s", SCRIPT_NAME, output)
    return nil
  end
  return stdnse.format_output(status, output)
end
