local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local nmap = require "nmap"
local shortport = require "shortport"
local ssh2 = require "ssh2"
local sslcert = require "sslcert"
local math = require "math"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects RSA keys vulnerable to Return Of Coppersmith Attack (ROCA) factorization.

SSH hostkeys and SSL/TLS certificates are checked. The checks require recent updates to the openssl NSE library.

References:
* https://crocs.fi.muni.cz/public/papers/rsa_ccs17
]]

---
-- @usage
-- nmap -p 22,443 --script rsa-vuln-roca <target>
--
-- @output
--
--@xmloutput
--
-- @see ssl-cert
-- @see ssh-hostkey

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

-- only run this script if the target host is NOT a private (RFC1918) IP address)
-- and the port is an open SSL service
portrule = function(host, port)
  if not openssl.bignum_div then
    stdnse.verbose1("This script requires the latest update to NSE's openssl library bindings.")
    return false
  end
  -- SSH key check
  return shortport.port_or_service(22, "ssh")
  -- same criteria as ssl-cert.nse
  or shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function is_vulnerable (modulus)
  local dec2bn = openssl.bignum_dec2bn
  -- Prime tests used under MIT license from https://github.com/crocs-muni/roca
  local prime_tests = nmap.registry.roca_prime_tests or {
    {dec2bn("3"), dec2bn("6")},
    {dec2bn("5"), dec2bn("30")},
    {dec2bn("7"), dec2bn("126")},
    {dec2bn("11"), dec2bn("1026")},
    {dec2bn("13"), dec2bn("5658")},
    {dec2bn("17"), dec2bn("107286")},
    {dec2bn("19"), dec2bn("199410")},
    {dec2bn("23"), dec2bn("8388606")},
    {dec2bn("29"), dec2bn("536870910")},
    {dec2bn("31"), dec2bn("2147483646")},
    {dec2bn("37"), dec2bn("67109890")},
    {dec2bn("41"), dec2bn("2199023255550")},
    {dec2bn("43"), dec2bn("8796093022206")},
    {dec2bn("47"), dec2bn("140737488355326")},
    {dec2bn("53"), dec2bn("5310023542746834")},
    {dec2bn("59"), dec2bn("576460752303423486")},
    {dec2bn("61"), dec2bn("1455791217086302986")},
    {dec2bn("67"), dec2bn("147573952589676412926")},
    {dec2bn("71"), dec2bn("20052041432995567486")},
    {dec2bn("73"), dec2bn("6041388139249378920330")},
    {dec2bn("79"), dec2bn("207530445072488465666")},
    {dec2bn("83"), dec2bn("9671406556917033397649406")},
    {dec2bn("89"), dec2bn("618970019642690137449562110")},
    {dec2bn("97"), dec2bn("79228162521181866724264247298")},
    {dec2bn("101"), dec2bn("2535301200456458802993406410750")},
    {dec2bn("103"), dec2bn("1760368345969468176824550810518")},
    {dec2bn("107"), dec2bn("50079290986288516948354744811034")},
    {dec2bn("109"), dec2bn("473022961816146413042658758988474")},
    {dec2bn("113"), dec2bn("10384593717069655257060992658440190")},
    {dec2bn("127"), dec2bn("144390480366845522447407333004847678774")},
    {dec2bn("131"), dec2bn("2722258935367507707706996859454145691646")},
    {dec2bn("137"), dec2bn("174224571863520493293247799005065324265470")},
    {dec2bn("139"), dec2bn("696898287454081973172991196020261297061886")},
    {dec2bn("149"), dec2bn("713623846352979940529142984724747568191373310")},
    {dec2bn("151"), dec2bn("1800793591454480341970779146165214289059119882")},
    {dec2bn("157"), dec2bn("126304807362733370595828809000324029340048915994")},
    {dec2bn("163"), dec2bn("11692013098647223345629478661730264157247460343806")},
    {dec2bn("167"), dec2bn("187072209578355573530071658587684226515959365500926")},
  }
  nmap.registry.roca_prime_tests = prime_tests

  --stdnse.debug1("Testing %s", openssl.bignum_bn2dec(modulus))
  for _, test in ipairs(prime_tests) do
    local prime, fingerprint = test[1], test[2]
    local _, bnshift = openssl.bignum_div(modulus, prime)
    -- prime is small, so bnshift is small. Safe to convert to Lua integer
    local string_shift = openssl.bignum_bn2dec(bnshift)
    local shift = math.tointeger(string_shift)
    if not shift then
      stdnse.debug1("Unable to convert %s to integer", string_shift)
      return nil
    end
    --stdnse.debug1("Testing mod %s, shift is %s", openssl.bignum_bn2dec(prime), shift)
    if not openssl.bignum_is_bit_set(fingerprint, shift) then
      stdnse.debug1("Not vulnerable")
      return nil
    end
  end
      stdnse.debug1("VULNERABLE!!!!!!")

  return "Vulnerable to ROCA"
end

local function ssl_get_modulus(host, port)
  local ok, cert = sslcert.getCertificate(host, port)
  if not ok then
    stdnse.debug1("failed to obtain SSL certificate")
    return nil
  end

  if cert.pubkey.type ~= "rsa" then
    stdnse.debug1("Non-RSA certificate, not vulnerable to ROCA")
    return nil
  end

  local modulus = cert.pubkey.modulus
  if not modulus then
    stdnse.debug1("No modulus available; upgrade Nmap?")
    return nil
  end
  return modulus
end

local function ssh_get_modulus(host, port)
  local key = ssh2.fetch_host_key( host, port, "ssh-rsa" )
  if not key then
    stdnse.debug1("No RSA hostkey, not vulnerable to ROCA")
    return nil
  end
  local _, e, n = string.unpack(">s4s4s4", key.fp_input)
  return openssl.bignum_bin2bn(n)
end

action = function(host, port)
  local vuln_table = {
    title = "ROCA: Vulnerable RSA generation",
    state = vulns.STATE.NOT_VULN,
    -- TODO: Update when CVE is scored
    --risk_factor = "High",
    description = [[
    The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM)
    firmware, such as versions before 0000000000000422 - 4.34, before
    000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles
    RSA key generation, which makes it easier for attackers to defeat various
    cryptographic protection mechanisms via targeted attacks, aka ROCA.
    ]],
    IDS = {CVE = "CVE-2017-15361"},
    references = {
      "https://crocs.fi.muni.cz/public/papers/rsa_ccs17",
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local modulus
  if shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port) then
    modulus = ssl_get_modulus(host, port)
  elseif shortport.port_or_service(22, "ssh")(host, port) then
    modulus = ssh_get_modulus(host, port)
  end

  if modulus and is_vulnerable(modulus) then
    vuln_table.state = vulns.STATE.VULN
  end
  return report:make_output(vuln_table)
end
