local http = require "http"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Php2Shell (CVE-2026-109619 and CVE-2026-109618) consists of two distinct vulnerabilities; however, they share common critical
traits: both affect unpatched PHP runtimes across multiple release branches and allow for unauthenticated remote code execution (RCE).

CVE-2026-109618:
In the event of an out-of-memory (OOM) error, PHP utilizes the longjmp() function to exit the current execution context and halt request
processing. Certain contexts fail to handle this abrupt exit correctly, leaving request memory in an uninitialized state before full allocation
cleanup can occur. The subsequent request cleanup procedure then reads from this uninitialized memory area or performs conditional branching
operations based on its residual contents. Attackers can leverage specific OOM-triggering strategies to consistently induce this condition,
leading to reliable remote code execution (RCE).

CVE-2026-109619:
PHP maintains several global states that temporarily point to active request memory. Under specific conditions, these global states
are either not reset properly or are incorrectly repopulated post-reset. Consequently, a global state continues to reference a memory
block that has already been deallocated, resulting in a Use-After-Free (UAF) condition. Subsequent incoming requests read this "stale",
uninitialized state or execute branching operations guided by it. Various manipulation strategies can reliably trigger this behavior,
yielding remote code execution (RCE).

References:
*https://nvd.nist.gov/vuln/detail/cve-2026-109619
*https://www.cve.org/CVERecord?id=CVE-2026-109619
*https://www.rapid7.com/trust/advisories/php-cve-2026-109618-cve-2026-109619/
*https://nvd.nist.gov/vuln/detail/cve-2026-109618
*https://www.cve.org/CVERecord?id=CVE-2026-109618
*https://ubuntu.com/security/CVE-2026-109618
]]

---
--
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-vuln-php2shell: 
-- |   VULNERABLE:
-- |   Php2Shell CVE 2026 109619/109618 - RCE
-- |     State: LIKELY VULNERABLE
-- |     IDs:  1:CVE-2026-109618  CVE:CVE-2026-109619
-- |     Risk factor: High  CVSSv4: CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
-- |       According to the scan results, there is a potential security vulnerability in this PHP version.
-- |             
-- |     Extra information:
-- |       PHP Version: 8.5.1 Potentially vulnerable.
-- |     References:
-- |       https://www.rapid7.com/trust/advisories/php-cve-2026-109618-cve-2026-109619/
-- |       https://ubuntu.com/security/CVE-2026-109619
-- |       https://www.cve.org/CVERecord?id=CVE-2026-109619
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619
-- |       https://www.cve.org/CVERecord?id=CVE-2026-109618
-- |       https://ubuntu.com/security/CVE-2026-109618
-- |       https://nvd.nist.gov/vuln/detail/cve-2026-109618
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2026-109619
--
---

author = "CyberWarrior1"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}

portrule = shortport.http

local function to_num(v)
  local a, b, c = string.match(v, "^(%d+)%.(%d+)%.(%d+)$")
  return tonumber(a) * 1000000 + tonumber(b) * 1000 + tonumber(c)
end

action = function(host, port)
    local vuln_table = {
      title = "Php2Shell CVE 2026 109619/109618 - RCE",
      IDS = {CVE = 'CVE-2026-109619', 'CVE-2026-109618'},
      state = vulns.STATE.UNKNOWN,
      risk_factor = "High",
      scores = {
        CVSSv4 = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      },
      description = [[
According to the scan results, there is a potential security vulnerability in this PHP version.
      ]],
      references = {
        "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
        "https://ubuntu.com/security/CVE-2026-109619",
        "https://www.cve.org/CVERecord?id=CVE-2026-109619",
        "https://www.rapid7.com/trust/advisories/php-cve-2026-109618-cve-2026-109619/",
        "https://nvd.nist.gov/vuln/detail/cve-2026-109618",
        "https://www.cve.org/CVERecord?id=CVE-2026-109618",
        "https://ubuntu.com/security/CVE-2026-109618"
      }
    }

    local vuln_versions = {
      {"5.4.0", "8.2.34"},
      {"8.3.0", "8.3.35"},
      {"8.4.0", "8.4.26"},
      {"8.5.0", "8.5.11"}
    }

    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    local response = http.get(host, port, "/")
    if not response or not response.status then
        return nil
    end

    local powered_by
    if response.header then
        for key, value in pairs(response.header) do
            if string.lower(key) == "x-powered-by" then
                powered_by = value
                break
            end
        end
    end

    if not powered_by then
        return nil
    end

    if not string.match(powered_by, "PHP/") then
        return nil
    end

    local php_version = string.match(
        powered_by,
        "PHP/(%d+%.%d+%.%d+)"
    )

    if not php_version then
        return nil
    end

    local is_vuln = false
    local n = to_num(php_version)
    for _, r in ipairs(vuln_versions) do
        if n >= to_num(r[1]) and n <= to_num(r[2]) then
            is_vuln = true
            break
        end
    end

    if is_vuln then
        vuln_table.state = vulns.STATE.LIKELY_VULN
        vuln_table.extra_info = string.format(
            "PHP Version: %s Potentially vulnerable.",
            php_version
        )
    else
        vuln_table.state = vulns.STATE.NOT_VULN
        vuln_table.extra_info = string.format(
            "PHP Version: %s Version not matched.",
            php_version
        )
    end
    return report:make_output(vuln_table)
end
