local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to use EHLO and HELP to gather the Extended commands supported by an
SMTP server.
]]

---
-- @usage
-- nmap --script smtp-commands.nse [--script-args smtp-commands.domain=<domain>] -pT:25,465,587 <host>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Microsoft ESMTP 6.0.3790.3959
-- | smtp-commands: SMTP.domain.com Hello [172.x.x.x], TURN, SIZE, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, X-EXPS GSSAPI NTLM LOGIN, X-EXPS=LOGIN, AUTH GSSAPI NTLM LOGIN, AUTH=LOGIN, X-LINK2STATE, XEXCH50, OK
-- |_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
--
-- @args smtp.domain or smtp-commands.domain Define the domain to be used in the SMTP commands.

-- changelog
-- 1.1.0.0 - 2007-10-12
-- + added HELP command in addition to EHLO
-- 1.2.0.0 - 2008-05-19
-- + made output single line, comma-delimited, instead of
--   CR LF delimited on multi-lines
-- + was able to use regular text and not hex codes
-- 1.3.0.0 - 2008-05-21
-- + more robust handling of problems
-- + uses verbosity and debugging to decide if you need to
--   see certain errors and if the output is in a line or
--   in , for lack of a better word, fancy format
-- + I am not able to do much testing because my new ISP blocks
--   traffic going to port 25 other than to their mail servers as
--   a "security" measure.
-- 1.3.1.0 - 2008-05-22
-- + minor tweaks to get it working when one of the requests fails
--   but not both of them.
-- 1.5.0.0 - 2008-08-15
-- + updated to use the nsedoc documentation system
-- 1.6.0.0 - 2008-10-06
-- + Updated gsubs to handle different formats, pulls out extra spaces
--   and normalizes line endings
-- 1.7.0.0 - 2008-11-10
-- + Better normalization of output, remove "250 " from EHLO output,
--   don't comma-separate HELP output.
-- 2.0.0.0 - 2010-04-19
-- + Complete rewrite based off of Arturo 'Buanzo' Busleiman's SMTP open
--   relay detector script.
-- 2.0.1.0 - 2010-04-27
-- + Incorporated advice from Duarte Silva (http://seclists.org/nmap-dev/2010/q2/277)
--   - 'domain' can be specified via a script-arg
--   - removed extra EHLO command that was redundant and not needed
--   - fixed two quit()s to include a return value
-- + To reiterate, this is a blatant cut and paste job of Arturo 'Buanzo'
--   Busleiman's SMTP open relay detector script and Duarte Silva's SMTP
--   user enumeration script.
--   Props to them for doing what they do and letting me ride on their coattails.
-- 2.1.0.0 - 2011-06-01
-- + Rewrite the script to use the smtp.lua library.

author = "Jasey DePriest"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service({ 25, 465, 587 },
  { "smtp", "smtps", "submission" })

function go(host, port)
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = true,
  }

  local domain = stdnse.get_script_args('smtp-commands.domain') or
  smtp.get_domain(host)

  local result, status = {}
  -- Try to connect to server.
  local socket, response = smtp.connect(host, port, options)
  if not socket then
    return false, string.format("Couldn't establish connection on port %i",
      port.number)
  end

  status, response = smtp.ehlo(socket, domain)
  if not status then
    return status, response
  end

  response = string.gsub(response, "250[%-%s]+", "") -- 250 or 250-
  response = string.gsub(response, "\r\n", "\n") -- normalize CR LF
  response = string.gsub(response, "\n\r", "\n") -- normalize LF CR
  response = string.gsub(response, "^\n+(.-)\n+$", "%1")
  response = string.gsub(response, "\n", ", ") -- LF to comma
  response = string.gsub(response, "%s+", " ") -- get rid of extra spaces
  table.insert(result,response)

  status, response = smtp.help(socket)
  if status then
    response = string.gsub(response, "214[%-%s]+", "") -- 214
    response = string.gsub(response, "^%s+(.-)%s+$", "%1")
    response = string.gsub(response, "%s+", " ") -- get rid of extra spaces
    table.insert(result,response)
    smtp.quit(socket)
  end

  return true, result
end

action = function(host, port)
  local status, result = go(host, port)

  -- The go function returned false, this means that the result is a simple error message.
  if not status then
    return result
  else
    if #result > 0 then
      local final = {}
      for index, test in ipairs(result) do
        table.insert(final, test)
      end
      return stdnse.strjoin("\n ", final)
    end
  end
end
