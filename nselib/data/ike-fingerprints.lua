local table = require 'table'

--[[
This is compiled list of known IKE vendor IDs.

Most of the VIDs have been copied from ike-scan with permission from
the original author, Roy Hills, so a big 'thank you' is in order.
-- http://www.nta-monitor.com/wiki/index.php/Ike-scan_Documentation

Unknown ids:
  ab926d9ee113a0219557fcc54e52865c (Citrix  NetScaler ?)
  5062b335bc20db32c0d54465a2f70100 (fortigate ?)
  4f4540454371496d7a684644 (linksys ?)
  9436e8d67174ef9aed068d5ad5213f187a3f8ba6000000160000061e (Netscreen 5XP running ScreenOS 4.0.r3)

]]

author = "Jesper Kueckelhahn"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"


fingerprints = {};

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- Vendor ID Fingerprints
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
-- Avaya
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Avaya',
  version = nil,
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^4485152d18b6bbcc0be8a8469579ddcc'
});



--------------------------------------------------------------------------------
-- Checkpoint
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = '4.1 Base',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000020000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = '4.1 SP1',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000000030000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = '4.1 SP2-SP6',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f0000000100000fa20000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG Base',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013880000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG FP1',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f00000001000013890000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG FP2',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138a0000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG FP3',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138b0000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG AI R54',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138c0000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NG AI R55',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d0000000000000000........'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = 'NGX',
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d........00000000........'
});

-- Catch all Checkpoint
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Checkpoint VPN-1 / Firewall-1',
  version = nil,
  ostype = nil,
  devicetype = 'security-misc',
  cpe =   nil,
  fingerprint = '^f4ed19e0c114eb516faaac0ee37daf2807b4381f'
});



--------------------------------------------------------------------------------
-- Cisco
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco VPN Concentrator 3000',
  version = '3.0.0',
  ostype = 'pSOS+',
  devicetype = 'security-misc',
  cpe = 'cpe:/h:cisco:concentrator',
  fingerprint = '^1f07f70eaa6514d3b0fa96542a500300'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco VPN Concentrator 3000',
  version = '3.0.1',
  ostype = 'pSOS+',
  devicetype = 'security-misc',
  cpe =   'cpe:/h:cisco:concentrator',
  fingerprint = '^1f07f70eaa6514d3b0fa96542a500301'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco VPN Concentrator 3000',
  version = '3.0.5',
  ostype = 'pSOS+',
  devicetype = 'security-misc',
  cpe =   'cpe:/h:cisco:concentrator',
  fingerprint = '^1f07f70eaa6514d3b0fa96542a500305'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco VPN Concentrator 3000',
  version = '4.0.7',
  ostype = 'pSOS+',
  devicetype = 'security-misc',
  cpe =   'cpe:/h:cisco:concentrator',
  fingerprint = '^1f07f70eaa6514d3b0fa96542a500407'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco VPN Concentrator 3000',
  version = nil,
  ostype = 'pSOS+',
  devicetype = 'security-misc',
  cpe =   'cpe:/h:cisco:concentrator',
  fingerprint = '^1f07f70eaa6514d3b0fa96542a......'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Cisco',
  version = nil,
  ostype = 'IOS',
  devicetype = 'security-misc',
  cpe =   'cpe:/h:cisco',
  fingerprint = '^3e984048'
});



--------------------------------------------------------------------------------
-- Fortinet
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Fortinet FortiGate',
  version = nil,
  ostype = nil,
  devicetype = 'Network Security Appliance',
  cpe =   'cpe:/h:fortinet:fortigate',
  fingerprint = '^1d6e178f6c2c0be284985465450fe9d4'
});



--------------------------------------------------------------------------------
-- FreeS/WAN
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.00',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.00',
  fingerprint = '^4f45486b7d44784d42676b5d'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.01',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.01',
  fingerprint = '^4f457c4f547e6e615b426e56'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.02',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.02',
  fingerprint = '^4f456c6b44696d7f6b4c4e60'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.03',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.03',
  fingerprint = '^4f45566671474962734e6264'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.04',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.04',
  fingerprint = '^4f45704f736579505c6e5f6d'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.05',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.05',
  fingerprint = '^4f457271785f4c7e496f4d54'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Linux FreeS/WAN',
  version = '2.06',
  ostype = 'Linux',
  devicetype = nil,
  cpe =   'cpe:/a::freeswan:2.06',
  fingerprint = '^4f457e4c466e5d427c5c6b52'
});



--------------------------------------------------------------------------------
-- Juniper
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = 'SSG-550M',
  ostype = 'NetScreen OS 6.20',
  devicetype = 'Firewall/VPN',
  cpe =   'cpe:/h:juniper:ssg-550m:6.20',
  fingerprint = '^2c9d7e81995b9967d23f571ac641f9348122f1cc1200000014060000'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper NetScreen',
  version = 'NS-5GT',
  ostype = 'NetScreen OS',
  devicetype = 'Firewall/VPN',
  cpe =   'cpe:/h:juniper:ns-5gt',
  fingerprint = '^166f932d55eb64d8e4df4fd37e2313f0d0fd8451'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = 'NS-5GT',
  ostype = 'NetScreen OS',
  devicetype = 'Firewall/VPN',
  cpe =   'cpe:/h:juniper:ns-5gt',
  fingerprint = '^4a4340b543e02b84c88a8b96a8af9ebe77d9accc'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = 'NS-5XP',
  ostype = 'NetScreen OS',
  devicetype = 'Firewall/VPN',
  cpe = 'cpe:/h:juniper:ns-5xp',
  fingerprint = '^299ee8289f40a8973bc78687e2e7226b532c3b76'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = 'NS-5XP',
  ostype = 'NetScreen OS',
  devicetype = 'Firewall/VPN',
  cpe = 'cpe:/h:juniper:ns-5xp',
  fingerprint = '^64405f46f03b7660a23be116a1975058e69e8387'
});


-- 9436e8d67174ef9aed068d5ad5213f187a3f8ba6000000160000061e (Netscreen 5XP running ScreenOS 4.0.r3) ?
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = 'NS-5XP',
  ostype = 'NetScreen OS',
  devicetype = 'Firewall/VPN',
  cpe = 'cpe:/h:juniper:ns-5xp',
  fingerprint = '^9436e8d67174ef9aed068d5ad5213f187a3f8ba6'
});


table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3a15e1f3cf2a63582e3ac82d1c64cbe3b6d779e7'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^47d2b126bfcd83489760e2cf8c5d4d5a03497c15'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^699369228741c6d4ca094c93e242c9de19e7b7c6'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8c0dc6cf62a0ef1b5c6eabd1b67ba69866adf16a'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^92d27a9ecb31d99246986d3453d0c3d57a222a61'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9b096d9ac3275a7d6fe8b91c583111b09efed1a0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^bf03746108d746c904f1f3547de24f78479fed12'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^c2e80500f4cc5fbf5daaeed3bb59abaeee56c652'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^c8660a62b03b1b6130bf781608d32a6a8d0fb89f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^f885da40b1e7a9abd17655ec5bbec0f21f0ed52e'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2a2bcac19b8e91b426107807e02e7249569d6fd3'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^a35bfd05ca1ac0b3d2f24e9e82bfcbff9c9e52b5'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Juniper',
  version = nil,
  ostype = 'NetScreen OS',
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4865617274426561745f4e6f74696679386b0100' -- (HeartBeat_Notify + 386b0100)
});


--------------------------------------------------------------------------------
-- KAME/racoon/IPSec Tools (for linux/BSD)
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'KAME/racoon/IPsec Tools',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7003cbc1097dbe9c2600ba6983bc8b35'
});



--------------------------------------------------------------------------------
-- Mac OS X
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Apple ',
  version = nil,
  ostype = 'Mac OS X',
  devicetype = nil,
  cpe = 'cpe:/a:apple:macosx',
  fingerprint = '^4d6163204f53582031302e78'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Apple ',
  version = nil,
  ostype = 'Mac OS X',
  devicetype = nil,
  cpe = 'cpe:/a:apple:macosx',
  fingerprint = '^4df37928e9fc4fd1b3262170d515c662'
});



--------------------------------------------------------------------------------
-- Microsoft
-- http://msdn.microsoft.com/en-us/library/cc233476.aspx
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows 2000',
  ostype = 'Windows 2000',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:2000',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000002'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows XP',
  ostype = 'Windows XP',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:XP',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000003'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows Server 2003',
  ostype = 'Windows Server 2003',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:server2003',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000004'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows Vista',
  ostype = 'Windows Vista',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:vista',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000005'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows Server 2008',
  ostype = 'Windows Server 2008',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:server2008',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000006'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows 7',
  ostype = 'Windows 7',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:7',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000007'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows Server 2008 R2',
  ostype = 'Windows Server 2008 R2',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:server2008r2',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000008'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows 8',
  ostype = 'Windows 8',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:8',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000009'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows Server 2012',
  ostype = 'Windows Server 2012',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows:server2012',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46100000010'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Microsoft',
  version = 'Windows',
  ostype = 'Windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e46.........'
});



--------------------------------------------------------------------------------
-- Nortel Contivity / Nortel VPN router
-- The last byte might be a version ?
-- From ike-scan:
--- 00000004, 00000005, 00000007, 00000009, 0000000a
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Nortel',
  version = 'Contivity / VPN router',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^424e4553000000..'
});



--------------------------------------------------------------------------------
-- OpenPGP
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'OpenPGP',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4f70656e504750'
});



--------------------------------------------------------------------------------
-- Openswan
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Openswan',
  version = '2.2.0',
  ostype = 'Linux 2.x',
  devicetype = nil,
  cpe = 'cpe:/o:linux:kernel:2.x',
  fingerprint = '^4f4548724b6e5e68557c604f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Openswan',
  version = '2.3.0',
  ostype = 'Linux 2.x',
  devicetype = nil,
  cpe = 'cpe:/o:linux:kernel:2.x',
  fingerprint = '^4f4572696f5c77557f746249'
});



--------------------------------------------------------------------------------
-- SafeNet
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SafeNet',
  version = '8.0.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310382e302e3020284275696c6420313029000000'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SafeNet Remote',
  version = '9.0.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310392e302e3120284275696c6420313229000000'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SafeNet Remote',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^47bbe7c993f1fc13b4e6d0db565c68e5'
});



--------------------------------------------------------------------------------
-- SonicWall
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5b362bc820f60001' -- SonicWall 3060 ?
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5b362bc820f60003'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5b362bc820f60006'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5b362bc820f60007' -- (Maybe NSA?, SonicOS Enhanced 4.2?)
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^404bf439522ca3f6'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SonicWall',
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^da8e937880010000' -- (Maybe TZ 170)
});



--------------------------------------------------------------------------------
-- SSH IPSec Express
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 1.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^fbf47614984031fa8e3bb6198089b223'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 1.1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^1952dc91ac20f646fb01cf42a33aee30'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 1.1.2',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^e8bffa643e5c8f2cd10fda7370b6ebe5'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 1.2.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^c1111b2dee8cbc3d620573ec57aab9cb'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 2.0.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7f21a596e4e318f0b2f4944c2384cb84'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 2.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2836d1fd2807bc9e5ae30786320451ec'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 2.1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^a68de756a9c5229bae66498040951ad5'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 2.1.2',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3f2372867e237c1cd8250a75559cae20'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 3.0.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^0e58d5774df602007d0b02443660f7eb'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 3.0.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^f5ce31ebc210f44350cf71265b57380f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 4.0.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^f64260af2e2742daddd56987068a99a0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 4.0.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7a54d3bdb3b1e6d923892064be2d981c'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 4.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9aa1f3b43472a45d5f506aeb260cf214'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 4.1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^89f7b760d86b012acf263382394d962f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 4.2.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^6880c7d026099114e486c55430e7abee'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 5.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b037a21aceccb5570f602546f97bde8c'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 5.0.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2b2dad97c4d140930053287f996850b0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 5.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^45e17f3abe93944cb202910c59ef806b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'IPSec Express 5.1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5925859f7377ed7816d2fb81c01fa551'
});


--------------------------------------------------------------------------------
-- SSH QuickSec
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 0.9.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^37eba0c4136184e7daf8562a77060b4a'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 1.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5d72925e55948a9661a7fc48fdec7ff9'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 1.1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^777fbf4c5af6d1cdd4b895a05bf82594'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 1.1.2',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2cdf08e712ede8a5978761267cd19b91'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 1.1.3',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^59e454a8c2cf02a34959121f1890bc87'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'QuickSec 2.1.0',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8f9cc94e01248ecdf147594c284b213b'
});



--------------------------------------------------------------------------------
-- SSH Sentinel
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^054182a07c7ae206f9d2cf9d2432c482'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel 1.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b91623e693ca18a54c6a2778552305e8'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel 1.2',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5430888de01a31a6fa8f60224e449958'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel 1.3',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7ee5cb85f71ce259c94a5c731ee4e752'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel 1.4',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^63d9a1a7009491b5a0a6fdeb2a8284f0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'SSH Communications Security',
  version = 'Sentinel 1.4.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^eb4b0d96276b4e220ad16221a7b2a5e6'
});



--------------------------------------------------------------------------------
-- Stonegate
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'StoneSoft',
  version = 'StoneGate',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^c573b056d7faca36c2fba28374127cbf'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'StoneSoft',
  version = 'StoneGate',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^baeb239037e17787d730eed9d95d48aa'
});



--------------------------------------------------------------------------------
-- strongSwan
-- http://www.strongswan.org/
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.3.6',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^882fe56d6fd20dbc2251613b2ebe5beb'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.2.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2d1f406118fbd5d28474791ffa00488a'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.2.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2a517d0d23c37d08bce7c292a0217b39'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.2.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^bab253f4cb10a8108a7c927c56c87886'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.2.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9f68901325a972894335302a9531ab9f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.11',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b7bd9f2f978e3259a7aa9f7a1396ad6c'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.10',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^bf3a89ae5bef8e72d44dac8bb88d7d5f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.9',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^78fdd287def01a3f074b5369eab4fd1c'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.8',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^66a2045507c119da78a4666259cdea48'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.7',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^ea840aa4dfc9712d6c32b5a16eb329a3'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.6',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^d19683368af4b0edc21ccde982b1d1b0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.5',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^bf0fbf7306ebb7827042d893539886e2'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^312f9cb1a6b90e19de7528c904ac3087'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5849ab6d8beabd6e4d09e5a3b88c089a'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^15a1ace7ee52fddfef04f928db2dd134'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^d3f1c488c368175d5f40a8f5ca5f5e12'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.1.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4794cef6843422980d1a3d06af41c5cd'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.7',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^ab0746221cc8fd0d5238f73a9b3da557'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.6',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4c90136946577b51919d8d9a6b8e4a9f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.5',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^dd180d21e5ce655a768ba32211dd8ad9'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^1ef283f83549b5ff9608b6d634f84d75'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b181b18e114fc209b3c6e26c3a80718e'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^77e8eea6f556a499de3ffe7f7f95661c'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9dbbafcf1db0dd595ae065294003ad3e'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '4.0.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^2ce9c946a4c879bf11b50b76cc5692cb'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.8',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8c4a3bcb729b11f703d22a5b39640ca8'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.7',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3a0d4e7ca4e492ed4dfe476d1ac6018b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.6',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^fe3f49706e26a9fb36a87bfce9ea36ce'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.5',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4c7efa31b39e510432a317570d97bbb9'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^76c72bfd398424dd001b86d0012fe061'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^fb4641ad0eeb2a34491d15f4eff51063'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^299932277b7dfe382ce23465333a7d23'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^e37f2d5ba89a62cd202ee27dac06c8a8'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.8.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^32f0e9b9c06dfe8c9ad5599a636971a1'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.7.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7f50cc4ebf04c2d9da73abfd69b77aa2'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.7.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^a194e2aaddd0bafb95253dd96dc733eb'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.7.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8134878582121785ba65ea345d6ba724'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.7.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^07fa128e4754f9447b1dd46374eef360'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.6.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b927f95219a0fe3600dba3c1182ae55f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.6.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b2860e7837f711bef3d0eeb106872ded'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.6.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^5b1cd6fe7d050eda6c93871c107db3d2'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.6.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^66afbc12bbfe6ce108b1f69f4bc917b7'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.6.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3f3266499ffdbd85950e702298062844'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.7',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^1f4442296b83d7e33a8b45209ba0e590'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.6',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3c5eba3d8564928e32ae43c3d9924dee'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.5',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^3f267ed621ada7ee6c7d8893ccb0b14b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7a6bf5b7df89642a75a78ef7d657c1c0'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^df5b1f0f1d5679d9f8512b16c55a6065'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^861ce5eb72164b190e9e629a31cf4901'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9a4a4648f60f8eda7cfcbfe271ee5b7d'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.5.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9eb3d907ed7ada4e3cbcacb917abc8e4'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.4.4',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^485a70361b4433b31dea1c6be0df243e'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.4.3',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^982b7a063a33c143a8eadc88249f6bcc'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.4.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^e7a3fd0c6d771a8f1b8a86a4169c9ea4'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.4.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^75b0653cb281eb26d31ede38c8e1e228'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.4.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^e829c88149bab3c0cee85da60e18ae9b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.3.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^42a4834c92ab9a7777063afa254bcb69'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.3.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^f697c1afcc2ec8ddcdf99dc7af03a67f'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.3.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b8f92b2fa2d3fe5fe158344bda1cc6ae'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.2.2',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^99dc7cc823376b3b33d04357896ae07b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.2.1',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^d9118b1e9de5efced9cc9d883f2168ff'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'strongSwan',
  version = '2.2.0',
  ostype = nil, -- Linux, Android, FreeBSD, Mac OS X
  devicetype = nil,
  cpe = nil,
  fingerprint = '^85b6cbec480d5c8cd9882c825ac2c244'
});



--------------------------------------------------------------------------------
-- Symantec
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Symantec',
  version = 'Raptor 8.1',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^526170746f7220506f77657256706e20536572766572205b56382e315d'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Symantec',
  version = 'Raptor',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^526170746f7220506f77657256706e20536572766572'
});



--------------------------------------------------------------------------------
-- Timestep
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Timestep',
  version = 'SGW 1520 315 2.01E013',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^54494d455354455020312053475720313532302033313520322e303145303133'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'Timestep',
  version = 'VPN Gateway',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^54494d4553544550'
});



--------------------------------------------------------------------------------
-- ZyXEL
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'ZyXEL',
  version = 'ZyWALL router',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^b858d1addd08c1e8adafea150608aa4497aa6cc8'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'ZyXEL',
  version = 'Zywall', -- Zyxel Zywall 2 / Zywall 30w / Zywall 70
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^625027749d5ab97f5616c1602765cf480a3b7d0b'
});

table.insert(fingerprints, {
  category = 'vendor',
  vendor = 'ZyXEL',
  version = 'ZyWALL USG',
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^f758f22668750f03b08df6ebe1d0'
});



--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- Attribute: Misc fingerprints
--     not directly usable for fingerprinting
--     but can be used for guessing
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- Microsoft
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^621b04bb09882ac1e15935fefa24aeee',
  text = 'GSSAPI'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^1e2b516905991c7d7c96fcbfb587e461',
  text = 'MS NT5 ISAKMPOAKLEY'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^ad2c0dd0b9c32083ccba25b8861ec455',
  text = 'A GSS-API Authentication Method for IKE'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^b46d8914f3aaa3f2fedeb7c7db2943ca',
  text = 'A GSS-API Authentication Method for IKE\\n'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^26244d38eddb61b3172a36e3d0cfb819',
  text = 'Microsoft Initial-Contact'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^fb1de3cdf341b7ea16b7e5be0855f120',
  text = 'MS-Negotiation Discovery Capable'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^e3a5966a76379fe707228231e5ce8652',
  text = 'IKE CGA version 1'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^214ca4faffa7f32d6748e5303395ae83',
  text = 'MS-MamieExists'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = 'Microsoft',
  version = nil,
  ostype = 'windows',
  devicetype = nil,
  cpe = 'cpe:/o:microsoft:windows',
  fingerprint = '^72872B95FCDA2EB708EFE322119B4971',
  text = 'NLBS_PRESENT'
});



--------------------------------------------------------------------------------
-- Other stuff
--------------------------------------------------------------------------------
table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^12f5f28c457168a9702d9fe274cc0100',
  text = 'Cisco Unity'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4048b7d56ebce88525e7de7f00d6c2d3',
  text = 'IKE FRAGMENTATION'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^afcad71368a1f1c96b8696fc77570100',
  text = 'Dead Peer Detection v1.0'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^afcad71368a1f1c96b8696fc7757....',
  text = 'Dead Peer Detection'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^09002689dfd6b712',
  text = 'XAUTH'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^325df29a2319f2dd',
  text = 'draft-krywaniuk-ipsec-antireplay-00'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^325df29a2319f2dd',
  text = 'draft-krywaniuk-ipsec-antireplay-00'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8db7a41811221660',
  text = 'draft-ietf-ipsec-heartbeats-00'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^50760f624c63e5c53eea386c685ca083',
  text = 'ESPThruNAT'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^c40fee00d5d39ddb1fc762e09b7cfea7',
  text = 'Testing NAT-T RFC'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4a131c81070358455c5728f20e95452f',
  text = 'RFC 3947 NAT-T'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^810fa565f8ab14369105d706fbd57279',
  text = 'RFC XXXX'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4865617274426561745f4e6f74696679',
  text = 'Heartbeat Notify'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4df37928e9fc4fd1b3262170d515c662',
  text = 'draft-ietf-ipsec-nat-t-ike'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4485152d18b6bbcd0be8a8469579ddcc',
  text = 'draft-ietf-ipsec-nat-t-ike-00'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^16f6ca16e4a4066d83821a0f0aeaa862',
  text = 'draft-ietf-ipsec-nat-t-ike-01'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^90cb80913ebb696e086381b5ec427b1f',
  text = 'draft-ietf-ipsec-nat-t-ike-02\\n'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^cd60464335df21f87cfdb2fc68b6a448',
  text = 'draft-ietf-ipsec-nat-t-ike-02'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^7d9419a65310ca6f2c179d9215529d56',
  text = 'draft-ietf-ipsec-nat-t-ike-03'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^9909b64eed937c6573de52ace952fa6b',
  text = 'draft-ietf-ipsec-nat-t-ike-04'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^80d0bb3def54565ee84645d4c85ce3ee',
  text = 'draft-ietf-ipsec-nat-t-ike-05'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^4d1e0e136deafa34c4f3ea9f02ec7285',
  text = 'draft-ietf-ipsec-nat-t-ike-06'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^439b59f8ba676c4c7737ae22eab8f582',
  text = 'draft-ietf-ipsec-nat-t-ike-07'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^8f8d83826d246b6fc7a8a6a428c11de8',
  text = 'draft-ietf-ipsec-nat-t-ike-08'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^42ea5b6f898d9773a575df26e7dd19e1',
  text = 'draft-ietf-ipsec-nat-t-ike-09'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^ba290499c24e84e53a1d83a05e5f00c9',
  text = 'IKE Challenge-Response'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^0d33611a5d521b5e3c9c03d2fc107e12',
  text = 'IKE Challenge-Response-2'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^ad3251042cdc4652c9e0734ce5de4c7d',
  text = 'IKE Challenge-Response Revised'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^13f11823f966fa91900f024ba66a86ba',
  text = 'IKE Challenge-Response Revised-2'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^27bab5dc01ea0760ea4e3190ac27c0d0',
  text = 'draft-stenberg-ipsec-nat-traversal-01'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^6105c422e76847e43f9684801292aecd',
  text = 'draft-stenberg-ipsec-nat-traversal-02'
});

table.insert(fingerprints, {
  category = 'attribute',
  vendor = nil,
  version = nil,
  ostype = nil,
  devicetype = nil,
  cpe = nil,
  fingerprint = '^6a7434c19d7e36348090a02334c9c805',
  text = 'draft-huttunen-ipsec-esp-in-udp-00.txt'
});



--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- vid_order:
--    By examining the ordering of the VIDs, some assumptions can be made
--    Currently only has support for Cisco


table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'IOS 12.3/12.4',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:ios:12.3-12.4',
  fingerprint = '^12f5f28c457168a9702d9fe274cc0100afcad71368a1f1c96b8696fc77570100................................09002689dfd6b712'
  -- Cisco Unity, Dead Peer Detection v1.0, junk, XAUTH
});

table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'PIX OS 6.0/6.1',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:pix:6.0-6.1',
  fingerprint = '^112f5f28c457168a9702d9fe274cc0100afcad71368a1f1c96b8696fc77570100................................'
  -- Cisco Unity, Dead Peer Detection, junk
});

table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'PIX OS 6.2.x',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:pix:6.2.x',
  fingerprint = '^09002689dfd6b71212f5f28c457168a9702d9fe274cc0100afcad71368a1f1c96b8696fc77570100................................'
  -- XAUTH, Cisco Unity, Dead Peer Detection, junk
});

table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'PIX OS 6.3.x',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:pix:6.3.x',
  fingerprint = '^09002689dfd6b712afcad71368a1f1c96b8696fc7757010012f5f28c457168a9702d9fe274cc0100................................'
  -- XAUTH, Dead Peer Detection v1.0, Cisco Unity, junk
});

table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'PIX OS 7.0.x',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:pix:7.0.x',
  fingerprint = '^12f5f28c457168a9702d9fe274cc010009002689dfd6b712afcad71368a1f1c96b8696fc775701004048b7d56ebce88525e7de7f00d6c2d3c00000001f07f70eaa6514d3b0fa96542a......'
  --Cisco Unity, XAUTH, Dead Peer Detection v1.0, IKE Fragmentation, Cisco VPN Concentrator
});

table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = nil,
  ostype = 'PIX OS 7.1 or later',
  devicetype = nil,
  cpe = 'cpe:/o:cisco:pix:7.1_or_later',
  fingerprint = '^12f5f28c457168a9702d9fe274cc010009002689dfd6b7124048b7d56ebce88525e7de7f00d6c2d3c00000001f07f70eaa6514d3b0fa96542a......'
  -- Cisco Unity, XAUTH, IKE Fragmentation, Cisco VPN Concentrator
});

--[[ Probably too
table.insert(fingerprints, {
  category = 'vid_ordering',
  vendor = 'Cisco',
  version = 'PIX OS 5.x OR IOS 12.0-12.2',
  ostype = 'PIX OS / IOS',
  devicetype = nil,
  cpe = 'cpe:/o:cisco',
  fingerprint = '^................................',
  -- 'random' VID, but fixed length
});
]]



--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- header_ordering:
--    For possible future use

--- Cisco
--   1: SA, VID, VID, VID, VID, KeyExchange, ID, Nonce, Hash
--   2: SA, KeyExchange, Nonce, ID, Hash, VID, VID, VID, VID, VID, VID
--   3: SA, KeyExchange, Nonce, ID, Hash, VID, VID, VID, VID, VID

--- Checkpoint
--   1: SA, VID  									             (Main)
--   2: SA, KeyExchange, Nonce, ID, VID, Hash  (Aggressive)

--- SonicWall
--   1: SA, VID                                (Main)
--   2: SA, KeyExchange, Nonce, ID, VID, Hash  (Aggressive)

--- Juniper
--   1: SA, VID, VID, VID
--   2: SA, VID, VID, VID, VID, VID

--- Zyxel
--   1: SA, VID, VID, VID, VID, VID, VID, VID, VID                (Zyxel USG 100)
--   2: SA, VID, VID, VID, VID, VID, VID, VID, VID, VID           (Zyxel USG 100)
--   3: SA, VID, VID                                              (Zyxel USG 200, ZyWall)
--   4: SA, KeyExchenge, Nonce, ID, Hash, VID, VID, Notification  (Zyxel USG 300)
--   5: SA, VID                                                   (???)
