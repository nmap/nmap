local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs a domain lookup using the edns-client-subnet option which
allows clients to specify the subnet that queries supposedly originate
from.  The script uses this option to supply a number of
geographically distributed locations in an attempt to enumerate as
many different address records as possible. The script also supports
requests using a given subnet.

* https://tools.ietf.org/html/rfc7871
]]

---
-- @usage
--   nmap -sU -p 53 --script dns-client-subnet-scan  --script-args \
--     'dns-client-subnet-scan.domain=www.example.com, \
--     dns-client-subnet-scan.address=192.168.0.1 \
--     [,dns-client-subnet-scan.nameserver=8.8.8.8] \
--     [,dns-client-subnet-scan.mask=24]' <target>
--   nmap --script dns-client-subnet-scan --script-args \
--     'dns-client-subnet-scan.domain=www.example.com, \
--     dns-client-subnet-scan.address=192.168.0.1 \
--     dns-client-subnet-scan.nameserver=8.8.8.8, \
--     [,dns-client-subnet-scan.mask=24]'
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-client-subnet-scan:
-- | www.google.com
-- |   1.2.3.4
-- |   5.6.7.8
-- |   9.10.11.12
-- |   13.14.15.16
-- |   .
-- |   .
-- |_  .
---
-- @args dns-client-subnet-scan.domain The domain to lookup eg. www.example.org
-- @args dns-client-subnet-scan.address The client subnet address to use
-- @args dns-client-subnet-scan.mask [optional] The number of bits to use as subnet mask (default: 24)
-- @args dns-client-subnet-scan.nameserver [optional] nameserver to use.  (default = host.ip)
--

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"discovery", "safe"}


local argNS = stdnse.get_script_args(SCRIPT_NAME .. '.nameserver')
local argDomain = stdnse.get_script_args(SCRIPT_NAME .. '.domain')
local argMask = stdnse.get_script_args(SCRIPT_NAME .. '.mask') or 24
local argAddr = stdnse.get_script_args(SCRIPT_NAME .. '.address')

prerule = function()
  return argDomain and nmap.address_family() == "inet"
end

portrule = function(host, port)
  if ( nmap.address_family() ~= "inet" ) then
    return false
  end
  if not shortport.port_or_service(53, "domain", {"tcp", "udp"})(host, port) then
    return false
  end
  -- only check tcp if udp is not open or open|filtered
  if port.protocol == 'tcp' then
    local tmp_port = nmap.get_port_state(host, {number=port.number, protocol="udp"})
    if tmp_port then
      return not string.match(tmp_port.state, '^open')
    end
  end
  return true
end

local areaIPs = {
  A4 = {ip=47763456, desc="GB,A4,Bath"},
  A5 = {ip=1043402336, desc="GB,A5,Biggleswade"},
  A6 = {ip=1364222182, desc="FR,A6,Chèvremont"},
  A7 = {ip=35357952, desc="GB,A7,Birmingham"},
  A8 = {ip=1050694009, desc="FR,A8,Romainville"},
  A9 = {ip=534257152, desc="FR,A9,Montpellier"},
  AB = {ip=2156920832, desc="CA,AB,Edmonton"},
  AK = {ip=202125312, desc="US,AK,Anchorage"},
  B1 = {ip=1041724648, desc="FR,B1,Robert"},
  B2 = {ip=35138048, desc="GB,B2,Bournemouth"},
  B3 = {ip=33949696, desc="FR,B3,Toulouse"},
  B4 = {ip=1050704998, desc="FR,B4,Lomme"},
  B5 = {ip=35213312, desc="GB,B5,Wembley"},
  B6 = {ip=773106752, desc="FR,B6,Amiens"},
  B7 = {ip=35148800, desc="GB,B7,Bristol"},
  B8 = {ip=786088496, desc="FR,B8,Valbonne"},
  B9 = {ip=33753088, desc="FR,B9,Lyon"},
  BC = {ip=201674096, desc="CA,BC,Victoria"},
  C1 = {ip=522223616, desc="FR,C1,Strasbourg"},
  C2 = {ip=41598976, desc="GB,C2,Halifax"},
  C3 = {ip=534676272, desc="GB,C3,Cambridge"},
  C5 = {ip=1043410032, desc="GB,C5,Runcorn"},
  C6 = {ip=773987544, desc="GB,C6,Saltash"},
  C7 = {ip=35165184, desc="GB,C7,Coventry"},
  C8 = {ip=35248128, desc="GB,C8,Croydon"},
  C9 = {ip=1892301824, desc="PH,C9,Iloilo"},
  D1 = {ip=35414016, desc="GB,D1,Darlington"},
  D2 = {ip=35164672, desc="GB,D2,Derby"},
  D3 = {ip=35301376, desc="GB,D3,Chesterfield"},
  D4 = {ip=1043450424, desc="GB,D4,Barnstaple"},
  D5 = {ip=2036385792, desc="PH,D5,Legaspi"},
  D7 = {ip=41451520, desc="GB,D7,Dudley"},
  D8 = {ip=35279104, desc="GB,D8,Durham"},
  D9 = {ip=460228608, desc="PH,D9,Manila"},
  DC = {ip=68514448, desc="US,DC,Washington"},
  E1 = {ip=1040645056, desc="GB,E1,Beverley"},
  E2 = {ip=35206912, desc="GB,E2,Brighton"},
  E3 = {ip=47822848, desc="GB,E3,Enfield"},
  E4 = {ip=39874560, desc="GB,E4,Colchester"},
  E5 = {ip=35270656, desc="GB,E5,Gateshead"},
  E6 = {ip=1368606720, desc="GB,E6,Coleford"},
  E7 = {ip=1051376056, desc="GB,E7,Woolwich"},
  E8 = {ip=1044737528, desc="GB,E8,Hackney"},
  F1 = {ip=1043451648, desc="GB,F1,Hammersmith"},
  F2 = {ip=35176448, desc="GB,F2,Basingstoke"},
  F4 = {ip=47998976, desc="GB,F4,Harrow"},
  F5 = {ip=1040622704, desc="GB,F5,Hart"},
  F6 = {ip=35230720, desc="GB,F6,Romford"},
  F8 = {ip=35214848, desc="GB,F8,Watford"},
  F9 = {ip=41693184, desc="GB,F9,Uxbridge"},
  G1 = {ip=41437184, desc="GB,G1,Hounslow"},
  G2 = {ip=35188224, desc="GB,G2,Ryde"},
  G3 = {ip=41861120, desc="GB,G3,Islington"},
  G4 = {ip=1040704992, desc="GB,G4,Kensington"},
  G5 = {ip=41506816, desc="GB,G5,Ashford"},
  G6 = {ip=786894336, desc="GB,G6,Hull"},
  G8 = {ip=40112128, desc="GB,G8,Huddersfield"},
  G9 = {ip=1380217968, desc="GB,G9,Knowsley"},
  H1 = {ip=1044731464, desc="GB,H1,Lambeth"},
  H2 = {ip=3512017264, desc="GB,H2,Earby"},
  H3 = {ip=35221504, desc="GB,H3,Leeds"},
  H4 = {ip=35158016, desc="GB,H4,Leicester"},
  H5 = {ip=1043402716, desc="GB,H5,Loughborough"},
  H6 = {ip=41732608, desc="GB,H6,Catford"},
  H7 = {ip=41863168, desc="GB,H7,Lincoln"},
  H8 = {ip=35294976, desc="GB,H8,Liverpool"},
  H9 = {ip=35196928, desc="GB,H9,London"},
  I1 = {ip=35253760, desc="GB,I1,Luton"},
  I2 = {ip=35263488, desc="GB,I2,Manchester"},
  I3 = {ip=47714304, desc="GB,I3,Rochester"},
  I4 = {ip=1298651136, desc="GB,I4,Morden"},
  I5 = {ip=1382961968, desc="GB,I5,Middlesborough"},
  I8 = {ip=1371219061, desc="GB,I8,Stepney"},
  I9 = {ip=35282944, desc="GB,I9,Norwich"},
  IA = {ip=201438272, desc="US,IA,Urbandale"},
  J1 = {ip=523578880, desc="GB,J1,Daventry"},
  J2 = {ip=788492344, desc="GB,J2,Grimsby"},
  J3 = {ip=3282790208, desc="GB,J3,Flixborough"},
  J5 = {ip=41759232, desc="GB,J5,Wallsend"},
  J6 = {ip=1043412268, desc="GB,J6,Alnwick"},
  J7 = {ip=41783296, desc="GB,J7,Harrogate"},
  J8 = {ip=35160064, desc="GB,J8,Nottingham"},
  J9 = {ip=47742976, desc="GB,J9,Newark"},
  JA = {ip=1476096512, desc="RU,JA,Kurilsk"},
  K1 = {ip=48015360, desc="GB,K1,Oldham"},
  K2 = {ip=1043402360, desc="GB,K2,Kidlington"},
  K3 = {ip=39956480, desc="GB,K3,Peterborough"},
  K4 = {ip=41735168, desc="GB,K4,Plymouth"},
  K5 = {ip=775747568, desc="GB,K5,Poole"},
  K6 = {ip=774162844, desc="GB,K6,Portsmouth"},
  K7 = {ip=41746432, desc="GB,K7,Reading"},
  K8 = {ip=35229696, desc="GB,K8,Ilford"},
  L1 = {ip=47773696, desc="GB,L1,Twickenham"},
  L2 = {ip=48103424, desc="GB,L2,Rochdale"},
  L3 = {ip=35304192, desc="GB,L3,Rotherham"},
  L4 = {ip=1043416984, desc="GB,L4,Oakham"},
  L5 = {ip=772988024, desc="GB,L5,Salford"},
  L6 = {ip=35336192, desc="GB,L6,Shrewsbury"},
  L7 = {ip=1043419464, desc="GB,L7,Oldbury"},
  L8 = {ip=39936000, desc="GB,L8,Lytham"},
  L9 = {ip=35304448, desc="GB,L9,Sheffield"},
  M1 = {ip=35384320, desc="GB,M1,Slough"},
  M2 = {ip=41470976, desc="GB,M2,Solihull"},
  M4 = {ip=35139584, desc="GB,M4,Southampton"},
  M5 = {ip=1043402176, desc="GB,M5,Southend-on-sea"},
  M6 = {ip=773986248, desc="GB,M6,Hill"},
  M8 = {ip=1443330688, desc="GB,M8,Camberwell"},
  M9 = {ip=35322880, desc="GB,M9,Stafford"},
  MB = {ip=1076550400, desc="CA,MB,Winnipeg"},
  MI = {ip=201393888, desc="US,MI,Saginaw"},
  N1 = {ip=1318741928, desc="GB,N1,Haydock"},
  N2 = {ip=35266560, desc="GB,N2,Stockport"},
  N3 = {ip=41832448, desc="GB,N3,Stockton-on-tees"},
  N4 = {ip=3231559680, desc="GB,N4,Longport"},
  N5 = {ip=1043424608, desc="GB,N5,Beccles"},
  N6 = {ip=35276800, desc="GB,N6,Sunderland"},
  N7 = {ip=41551872, desc="GB,N7,Tadworth"},
  N8 = {ip=41697280, desc="GB,N8,Sutton"},
  N9 = {ip=35252736, desc="GB,N9,Swindon"},
  NB = {ip=2211053568, desc="CA,NB,Fredericton"},
  ND = {ip=201473536, desc="US,ND,Bismarck"},
  NH = {ip=201772808, desc="US,NH,Laconia"},
  NJ = {ip=201352704, desc="US,NJ,Piscataway"},
  NS = {ip=3226164992, desc="CA,NS,Halifax"},
  NT = {ip=3332472320, desc="CA,NT,Yellowknife"},
  NV = {ip=202261184, desc="US,NV,Henderson"},
  O2 = {ip=40251392, desc="GB,O2,Telford"},
  O3 = {ip=35230208, desc="GB,O3,Grays"},
  O4 = {ip=35318784, desc="GB,O4,Torquay"},
  O5 = {ip=1368498352, desc="GB,O5,Poplar"},
  O6 = {ip=1546138112, desc="GB,O6,Stretford"},
  O7 = {ip=35219456, desc="GB,O7,Wakefield"},
  O8 = {ip=35321856, desc="GB,O8,Walsall"},
  O9 = {ip=1359108248, desc="GB,O9,Walthamstow"},
  ON = {ip=201620304, desc="CA,ON,Ottawa"},
  P1 = {ip=1043431736, desc="GB,P1,Wandsworth"},
  P2 = {ip=35260416, desc="GB,P2,Warrington"},
  P3 = {ip=41766912, desc="GB,P3,Nuneaton"},
  P4 = {ip=41893888, desc="GB,P4,Newbury"},
  P5 = {ip=772987648, desc="GB,P5,Westminster"},
  P7 = {ip=41466624, desc="GB,P7,Wigan"},
  P8 = {ip=48087808, desc="GB,P8,Salisbury"},
  P9 = {ip=41793536, desc="GB,P9,Maidenhead"},
  Q1 = {ip=41457664, desc="GB,Q1,Wallasey"},
  Q2 = {ip=1040739840, desc="GB,Q2,Wokingham"},
  Q3 = {ip=35323392, desc="GB,Q3,Wolverhampton"},
  Q4 = {ip=539624744, desc="GB,Q4,Redditch"},
  Q5 = {ip=1043415688, desc="GB,Q5,Wetherby"},
  Q6 = {ip=1043439984, desc="GB,Q6,Antrim"},
  Q7 = {ip=41811456, desc="GB,Q7,Newtownards"},
  Q8 = {ip=1347208672, desc="GB,Q8,Armagh"},
  Q9 = {ip=1044726432, desc="GB,Q9,Connor"},
  QC = {ip=2210594816, desc="CA,QC,Varennes"},
  R1 = {ip=1482707288, desc="GB,R1,Ballymoney"},
  R3 = {ip=47828992, desc="GB,R3,Belfast"},
  R4 = {ip=1051352576, desc="GB,R4,Eden"},
  R5 = {ip=1056827328, desc="GB,R5,Castlereagh"},
  R6 = {ip=47895040, desc="GB,R6,Coleraine"},
  R7 = {ip=3270400320, desc="GB,R7,Dunmore"},
  R8 = {ip=1367996672, desc="GB,R8,Portadown"},
  R9 = {ip=773985608, desc="GB,R9,Square"},
  RI = {ip=67285760, desc="US,RI,Providence"},
  S1 = {ip=1040409048, desc="GB,S1,Drummond"},
  S2 = {ip=1353842208, desc="GB,S2,Enniskillen"},
  S3 = {ip=1368133632, desc="GB,S3,Larne"},
  S4 = {ip=1446384520, desc="GB,S4,Ardmore"},
  S5 = {ip=1043419184, desc="GB,S5,Lisburn"},
  S6 = {ip=1056826304, desc="GB,S6,Londonderry"},
  S7 = {ip=1359111383, desc="GB,S7,Curran"},
  S8 = {ip=1369435392, desc="GB,S8,Waterfoot"},
  S9 = {ip=1043434592, desc="GB,S9,Newry"},
  T1 = {ip=3242033152, desc="GB,T1,Jordanstown"},
  T2 = {ip=1043402000, desc="GB,T2,Bangor"},
  T3 = {ip=1043429728, desc="GB,T3,Omagh"},
  T4 = {ip=1043429520, desc="GB,T4,Strabane"},
  T5 = {ip=39849984, desc="GB,T5,Aberdeen"},
  T6 = {ip=1043407024, desc="GB,T6,Inverurie"},
  T7 = {ip=47917056, desc="GB,T7,Forfar"},
  T8 = {ip=1051457600, desc="GB,T8,Sandbank"},
  T9 = {ip=1043429424, desc="GB,T9,Melrose"},
  TX = {ip=201673024, desc="US,TX,Mckinney"},
  U1 = {ip=1043400976, desc="GB,U1,Alloa"},
  U2 = {ip=1353815544, desc="GB,U2,Langholm"},
  U3 = {ip=1042190336, desc="GB,U3,Dundee"},
  U4 = {ip=1043428036, desc="GB,U4,Newmilns"},
  U5 = {ip=1051334704, desc="GB,U5,Bishopbriggs"},
  U6 = {ip=1040628912, desc="GB,U6,Musselburgh"},
  U7 = {ip=1056881248, desc="GB,U7,Barrhead"},
  U8 = {ip=35188736, desc="GB,U8,Edinburgh"},
  U9 = {ip=1318744616, desc="GB,U9,Blackstone"},
  V1 = {ip=47947776, desc="GB,V1,Kirkcaldy"},
  V2 = {ip=35190784, desc="GB,V2,Glasgow"},
  V4 = {ip=1043417560, desc="GB,V4,Greenock"},
  V5 = {ip=3570359128, desc="GB,V5,Borthwick"},
  V6 = {ip=1398983520, desc="GB,V6,Findhorn"},
  V7 = {ip=1043452928, desc="GB,V7,Saltcoats"},
  V8 = {ip=523564544, desc="GB,V8,Bothwell"},
  V9 = {ip=1353706504, desc="GB,V9,Redland"},
  VT = {ip=201355264, desc="US,VT,Brattleboro"},
  W1 = {ip=1042195200, desc="GB,W1,Perth"},
  W2 = {ip=1043412560, desc="GB,W2,Paisley"},
  W4 = {ip=1056825616, desc="GB,W4,Dundonald"},
  W5 = {ip=1040411544, desc="GB,W5,Douglas"},
  W6 = {ip=41547776, desc="GB,W6,Stirling"},
  W7 = {ip=1443523584, desc="GB,W7,Bearsden"},
  W8 = {ip=534572928, desc="GB,W8,Cross"},
  W9 = {ip=1042221056, desc="GB,W9,Livingston"},
  WA = {ip=201806720, desc="US,WA,Issaquah"},
  WY = {ip=135495936, desc="US,WY,Casper"},
  X1 = {ip=1043425760, desc="GB,X1,Valley"},
  X2 = {ip=773988152, desc="GB,X2,Victoria"},
  X3 = {ip=35149824, desc="GB,X3,Bridgend"},
  X4 = {ip=1043402272, desc="GB,X4,Blackwood"},
  X5 = {ip=39946240, desc="GB,X5,Cardiff"},
  X6 = {ip=1043435700, desc="GB,X6,Aberystwyth"},
  X7 = {ip=1043408760, desc="GB,X7,Llanelli"},
  X8 = {ip=1368926208, desc="GB,X8,Abergele"},
  X9 = {ip=1043411032, desc="GB,X9,Rhyl"},
  Y1 = {ip=1043407256, desc="GB,Y1,Holywell"},
  Y2 = {ip=1043401576, desc="GB,Y2,Caernarfon"},
  Y4 = {ip=1043428692, desc="GB,Y4,Cwmbran"},
  Y5 = {ip=3265794544, desc="GB,Y5,Cwmafan"},
  Y6 = {ip=35153920, desc="GB,Y6,Newport"},
  Y7 = {ip=1353763984, desc="GB,Y7,Haverfordwest"},
  Y8 = {ip=1043430344, desc="GB,Y8,Welshpool"},
  Z1 = {ip=40116224, desc="GB,Z1,Swansea"},
  Z2 = {ip=40189952, desc="GB,Z2,Pontypool"},
  Z3 = {ip=35147776, desc="GB,Z3,Barry"},
  Z4 = {ip=40321024, desc="GB,Z4,Wrexham"}
}

local get_addresses = function(address, mask, domain, nameserver, port)

  -- translate the IP's in the areaIPs to strings, as this is what the
  -- DNS library expects
  if ( "number" == type(address) ) then
    address = ipOps.fromdword(address)
  end

  local subnet = { family = nmap.address_family(), address = address, mask = mask }
  local status, resp = dns.query(domain, {host = nameserver, port=port.number, protocol=port.protocol, retAll=true, subnet=subnet})
  if ( not(status) ) then
    return {}
  end
  if ( "table" ~= type(resp) ) then resp = { resp } end
  return resp
end

action = function(host, port)

  if ( not(argDomain) ) then
    return stdnse.format_output(false, SCRIPT_NAME .. ".domain was not specified")
  end

  local nameserver = (host and host.ip) or argNS
  -- if we have no nameserver argument and no host, we don't have sufficient
  -- information to continue, abort
  if not nameserver then
    return nil
  end

  -- if we are running as a prerule pick some defaults
  port = port or { number = "53", protocol ="udp" }

  local addrs = argAddr or areaIPs
  if ( "string" == type(addrs) ) then addrs = {{ ip = addrs }} end

  local lookup, result = {}, { name = argDomain }
  for _,ip in pairs(addrs) do
    for _, addr in ipairs( get_addresses (ip.ip, argMask, argDomain, nameserver, port) ) do
      lookup[addr] = true
    end
  end
  for addr in pairs(lookup) do table.insert(result, addr) end
  table.sort(result)
  return stdnse.format_output(true, result)
end
