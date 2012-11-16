local http = require "http"
local io = require "io"
local json = require "json"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local tab = require "tab"
local table = require "table"

description = [[
Checks whether a file has been determined as malware by Virustotal. Virustotal
is a service that provides the capability to scan a file or check a checksum
against a number of the major antivirus vendors. The script uses the public
API which requires a valid API key and has a limit on 4 queries per minute.
A key can be acquired by registering as a user on the virustotal web page:
* http://www.virustotal.com

The scripts supports both sending a file to the server for analysis or
checking whether a checksum (supplied as an argument or calculated from a
local file) was previously discovered as malware.

As uploaded files are queued for analysis, this mode simply returns a URL
where status of the queued file may be checked.
]]

---
-- @usage
-- nmap --script http-virustotal --script-args='apikey="<key>",checksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"'
--
-- @output
-- Pre-scan script results:
-- | http-virustotal: 
-- |   Permalink: https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/1333633817/
-- |   Scan date: 2012-04-05 13:50:17
-- |   Positives: 41
-- |   digests
-- |     SHA1: 3395856ce81f2b7382dee72602f798b642f14140
-- |     SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
-- |     MD5: 44d88612fea8a8f36de82e1278abb02f
-- |   Results
-- |     name                  result                          date      version
-- |     AhnLab-V3             EICAR_Test_File                 20120404  2012.04.05.00
-- |     AntiVir               Eicar-Test-Signature            20120405  7.11.27.24
-- |     Antiy-AVL             AVTEST/EICAR.ETF                20120403  2.0.3.7
-- |     Avast                 EICAR Test-NOT virus!!!         20120405  6.0.1289.0
-- |     AVG                   EICAR_Test                      20120405  10.0.0.1190
-- |     BitDefender           EICAR-Test-File (not a virus)   20120405  7.2
-- |     ByteHero              -                               20120404  1.0.0.1
-- |     CAT-QuickHeal         EICAR Test File                 20120405  12.00
-- |     ClamAV                Eicar-Test-Signature            20120405  0.97.3.0
-- |     Commtouch             EICAR_Test_File                 20120405  5.3.2.6
-- |     Comodo                Exploit.EICAR-Test-File         20120405  12000
-- |     DrWeb                 EICAR Test File (NOT a Virus!)  20120405  7.0.1.02210
-- |     Emsisoft              EICAR-ANTIVIRUS-TESTFILE!IK     20120405  5.1.0.11
-- |     eSafe                 EICAR Test File                 20120404  7.0.17.0
-- |     eTrust-Vet            the EICAR test string           20120405  37.0.9841
-- |     F-Prot                EICAR_Test_File                 20120405  4.6.5.141
-- |     F-Secure              EICAR_Test_File                 20120405  9.0.16440.0
-- |     Fortinet              EICAR_TEST_FILE                 20120405  4.3.392.0
-- |     GData                 EICAR-Test-File                 20120405  22
-- |     Ikarus                EICAR-ANTIVIRUS-TESTFILE        20120405  T3.1.1.118.0
-- |     Jiangmin              EICAR-Test-File                 20120331  13.0.900
-- |     K7AntiVirus           EICAR_Test_File                 20120404  9.136.6595
-- |     Kaspersky             EICAR-Test-File                 20120405  9.0.0.837
-- |     McAfee                EICAR test file                 20120405  5.400.0.1158
-- |     McAfee-GW-Edition     EICAR test file                 20120404  2012.1
-- |     Microsoft             Virus:DOS/EICAR_Test_File       20120405  1.8202
-- |     NOD32                 Eicar test file                 20120405  7031
-- |     Norman                Eicar_Test_File                 20120405  6.08.03
-- |     nProtect              EICAR-Test-File                 20120405  2012-04-05.01
-- |     Panda                 EICAR-AV-TEST-FILE              20120405  10.0.3.5
-- |     PCTools               Virus.DOS.EICAR_test_file       20120405  8.0.0.5
-- |     Rising                EICAR-Test-File                 20120405  24.04.02.03
-- |     Sophos                EICAR-AV-Test                   20120405  4.73.0 TP
-- |     SUPERAntiSpyware      NotAThreat.EICAR[TestFile]      20120402  4.40.0.1006
-- |     Symantec              EICAR Test String               20120405  20111.2.0.82
-- |     TheHacker             EICAR_Test_File                 20120405  6.7.0.1.440
-- |     TrendMicro            Eicar_test_file                 20120405  9.500.0.1008
-- |     TrendMicro-HouseCall  Eicar_test_file                 20120405  9.500.0.1008
-- |     VBA32                 EICAR-Test-File                 20120405  3.12.16.4
-- |     VIPRE                 EICAR (v)                       20120405  11755
-- |     ViRobot               EICAR-test                      20120405  2012.4.5.5025
-- |_    VirusBuster           EICAR_test_file                 20120404  14.2.11.0
--
-- @args apikey an API key acquired from the virustotal web page
-- @args upload true if the file should be uploaded and scanned, false if a
--       checksum should be calculated of the local file (default: false)
-- @args filename the full path of the file to checksum or upload
-- @args checksum a SHA1, SHA256, MD5 checksum of a file to check
--


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories={"safe", "malware", "external"}


local arg_apiKey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey")
local arg_upload = stdnse.get_script_args(SCRIPT_NAME .. ".upload") or false
local arg_filename = stdnse.get_script_args(SCRIPT_NAME .. ".filename")
local arg_checksum = stdnse.get_script_args(SCRIPT_NAME .. ".checksum")

prerule = function() return true end

local function readFile(filename)
	local f = io.open(filename, "r")
	if ( not(f) ) then
		return false, ("Failed to open file: %s"):format(filename)
	end
	
	local str = f:read("*all")
	if ( not(str) ) then
		f:close()
		return false, "Failed to read file contents"
	end
	f:close()
	return true, str
end

local function requestFileScan(filename)
	local status, str = readFile(filename)
	if ( not(status) ) then
		return false, str
	end
	
	local shortfile = filename:match("^.*[\\/](.*)$")
	local boundary = "----------------------------nmapboundary"
	local header = { ["Content-Type"] = ("multipart/form-data; boundary=%s"):format(boundary) }
	local postdata = ("--%s\r\n"):format(boundary)
	postdata = postdata .. "Content-Disposition: form-data; name=\"apikey\"\r\n\r\n"
	postdata = postdata .. arg_apiKey .. "\r\n"
	postdata = postdata .. ("--%s\r\n" ..
		"Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n" ..
		"Content-Type: text/plain\r\n\r\n%s\r\n--%s--\r\n"):format(boundary, shortfile, str, boundary)
	
	local host = "www.virustotal.com"
	local port = { number = 80, protocol = "tcp" }
	local path = "/vtapi/v2/file/scan"
	
	local response = http.post( host, port, path, { header = header }, nil, postdata )
	if ( not(response) or response.status ~= 200 ) then
		return false, "Failed to request file scan"
	end

	local status, json_data = json.parse(response.body)
	if ( not(status) ) then
		return false, "Failed to parse JSON response"
	end
		
	return true, json_data
end

local function getFileScanReport(resource)

	local host = "www.virustotal.com"
	local port = { number = 80, protocol = "tcp" }
	local path = "/vtapi/v2/file/report"
	

	local response = http.post(host, port, path, nil, nil, { ["apikey"] = arg_apiKey, ["resource"] = resource })
	if ( not(response) or response.status ~= 200 ) then
		return false, "Failed to retrieve scan report"
	end

	local status, json_data = json.parse(response.body)
	if ( not(status) ) then
		return false, "Failed to parse JSON response"
	end
		
	return true, json_data
end

local function calcSHA256(filename)
	
	local status, str = readFile(filename)
	if ( not(status) ) then
		return false, str
	end
	return true, stdnse.tohex(openssl.digest("sha256", str))
end

local function parseScanReport(report)
	local result = {}
	
	table.insert(result, ("Permalink: %s"):format(report.permalink))
	table.insert(result, ("Scan date: %s"):format(report.scan_date))
	table.insert(result, ("Positives: %s"):format(report.positives))
	table.insert(result, { 
		name = "digests", 
		("SHA1: %s"):format(report.sha1),
		("SHA256: %s"):format(report.sha256),
		("MD5: %s"):format(report.md5)
	})
	
	local tmp = {}
	for name, scanres in pairs(report.scans) do
		local res = ( scanres.detected ) and scanres.result or "-"
		table.insert(tmp, { name = name, result = res, update = scanres.update, version = scanres.version })
	end
	table.sort(tmp, function(a,b) return a.name:upper()<b.name:upper() end)

	local scan_tbl = tab.new(4)
	tab.addrow(scan_tbl, "name", "result", "date", "version")
	for _, v in ipairs(tmp) do
		tab.addrow(scan_tbl, v.name, v.result, v.update, v.version)
	end
	table.insert(result, { name = "Results", tab.dump(scan_tbl) })
	
	return result
end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

action = function()
	
	if ( not(arg_apiKey) ) then
		return fail("An API key is required in order to use this script (see description)")
	end

	local resource
	if ( arg_upload == "true" and arg_filename ) then
		local status, json_data = requestFileScan(arg_filename, arg_apiKey)
		if ( not(status) or not(json_data['resource']) ) then
			return fail(json_data)
		end
		resource = json_data['resource']

		local output = {}
		table.insert(output, "Your file was succesfully uploaded and placed in the scanning queue.")
		table.insert(output, { name = "To check the current status visit:", json_data['permalink'] })
		return stdnse.format_output(true, output)
	elseif ( arg_filename ) then
		local status, sha256 = calcSHA256(arg_filename)
		if ( not(status) ) then
			return fail("Failed to calculate SHA256 checksum for file")
		end
		resource = sha256
	elseif ( arg_checksum ) then
		resource = arg_checksum
	else
		return
	end
	
	local status, response
	
	local status, response = getFileScanReport(resource)
	if ( not(status) ) then
		return fail("Failed to retrieve file scan report")
	end
			
	if ( not(response.response_code) or 0 == tonumber(response.response_code) ) then
		return fail(("Failed to retreive scan report for resource: %s"):format(resource))
	end
	
	return stdnse.format_output(true, parseScanReport(response))
end
