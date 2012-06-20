local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Tries to detect the presence of a web application firewall and its type and
version.

This works by sending a number of requests and looking in the responses for
known behavior and fingerprints such as Server header, cookies and headers
values. Intensive mode works by sending additional WAF specific requests to
detect certain behaviour.

Credit to wafw00f and w3af for some fingerprints.
]]

---
-- @args http-waf-fingerprint.root The base path. Defaults to <code>/</code>.
-- @args http-waf-fingerprint.intensive If set, will add WAF specific scans,
-- which takes more time. Off by default.
--
-- @usage
-- nmap --script=http-waf-fingerprint <targets>
-- nmap --script=http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 <targets>
--
--@output
--PORT   STATE SERVICE REASON
--80/tcp open  http    syn-ack
--| http-waf-fingerprint: 
--|   Detected WAF
--|_    BinarySec version 3.2.2

author = "Hani Benhabiles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

--
-- Version 0.1:
-- - Initial version based on work done with wafw00f and w3af.
-- - Removed many false positives.
-- - Added fingeprints for WAFs such as Incapsula WAF, Cloudflare, USP-SES,
--   Cisco ACE XML Gateway and ModSecurity.
-- - Added fingerprints and version detection for Webknight and BinarySec,
--   Citrix Netscaler and ModSecurity
--
-- Version 0.2:
-- - Added intensive mode.
-- - Added fingerprints for Naxsi waf in intensive mode.
--
-- TODO:    Fingerprints for other WAFs
--

portrule = shortport.service("http")

-- Each WAF has a table with name, version and detected keys
-- as well as a match function.
-- HTTP Responses are passed to match function which will alter detected
-- and version values after analyzing responses if adequate fingerprints
-- are found.

local bigip
bigip = {
    name = "F5 BigIP",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            
            if response.header['x-cnection'] then
                stdnse.print_debug("%s BigIP detected through X-Cnection header.", SCRIPT_NAME)
                bigip.detected = true
                return
            end
            
            if response.header.server == 'BigIP' then -- 
                stdnse.print_debug("%s BigIP detected through Server header.", SCRIPT_NAME)
                bigip.detected = true
                return
            end
            
            for _, cookie in pairs(response.cookies) do --
                if string.find(cookie.name, "BIGipServer") then
                    stdnse.print_debug("%s BigIP detected through cookies.", SCRIPT_NAME)
                    bigip.detected = true
                    return
                end
                -- Application Security Manager module
                if string.match(cookie.name, 'TS%w+') and string.len(cookie.name) <= 8 then
                    stdnse.print_debug("%s F5 ASM detected through cookies.", SCRIPT_NAME)
                    bigip.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local webknight
webknight = {
    name = "Webknight",
    detected = false,
    version = nil,

    match = function(responses)
        for name, response in pairs(responses) do
            if response.header.server and string.find(response.header.server, 'WebKnight/') then -- 
                stdnse.print_debug("%s WebKnight detected through Server Header.", SCRIPT_NAME)
                webknight.version = string.sub(response.header.server, 11)
                webknight.detected = true
                return 
            end
            if response.status == 999 then
                if not webknight.detected then stdnse.print_debug("%s WebKnight detected through 999 response status code.", SCRIPT_NAME) end
                webknight.detected = true
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local isaserver
isaserver = {
    name = "ISA Server",
    detected = false,
    version = nil,
    -- TODO Check if version detection is possible
    -- based on the response reason
    reason = {"Forbidden %( The server denied the specified Uniform Resource Locator %(URL%). Contact the server administrator.  %)",
              "Forbidden %( The ISA Server denied the specified Uniform Resource Locator %(URL%)"  
             },

    match = function(responses)
        for _, response in pairs(responses) do
            for _, reason in pairs(isaserver.reason) do --
                if http.response_contains(response, reason, true) then -- TODO Replace with something more performant
                    stdnse.print_debug("%s ISA Server detected through response reason.", SCRIPT_NAME)
                    isaserver.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local airlock
airlock = {
    name = "Airlock",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            for _, cookie in pairs(response.cookies) do --
                -- TODO Check if version detection is possible
                -- based on the difference in cookies name
                if cookie.name == "AL_LB" and string.sub(cookie.value, 1, 4) == '$xc/' then
                    stdnse.print_debug("%s Airlock detected through AL_LB cookies.", SCRIPT_NAME)
                    airlock.detected = true
                    return
                end
                if cookie.name == "AL_SESS" and (string.sub(cookie.value, 1, 5) == 'AAABL' 
                      or string.sub(cookie.value, 1, 5) == 'LgEAA' )then
                    stdnse.print_debug("%s Airlock detected through AL_SESS cookies.", SCRIPT_NAME)
                    airlock.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local barracuda
barracuda = {
    name = "Barracuda",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            for _, cookie in pairs(response.cookies) do
                if cookie.name == "barra_counter_session" then
                    stdnse.print_debug("%s Barracuda detected through cookies.", SCRIPT_NAME)
                    barracuda.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local denyall
denyall = {
    name = "Denyall",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            for _, cookie in pairs(response.cookies) do
                -- TODO Check accuracy
                if cookie.name == "sessioncookie" then
                    stdnse.print_debug("%s Denyall detected through cookies.", SCRIPT_NAME)
                    denyall.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local f5trafficshield 
f5trafficshield = {
    name = "F5 Traffic Shield",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            -- TODO Check for version detection possibility
            -- based on the cookie name / server header presence
            if response.header.server == "F5-TrafficShield" then
                stdnse.print_debug("%s F5 Traffic Shield detected through Server header.", SCRIPT_NAME)
                f5trafficshield.detected = true
                return
            end
            
            for _, cookie in pairs(response.cookies) do
                if cookie.name == "ASINFO" then
                    stdnse.print_debug("%s F5 Traffic Shield detected through cookies.", SCRIPT_NAME)
                    f5trafficshield.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local teros 
teros = {
    name = "Teros / Citrix Application Firewall Enterprise", -- CAF EX, according to citrix documentation 
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            for _, cookie in pairs(response.cookies) do
                if cookie.name == "st8id" or cookie.name == "st8_wat" or cookie.name == "st8_wlf" then
                    stdnse.print_debug("%s Teros / CAF detected through cookies.", SCRIPT_NAME)
                    teros.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local binarysec 
binarysec = {
    name = "BinarySec",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server and string.find(response.header.server, 'BinarySEC/') then -- 
                stdnse.print_debug("%s BinarySec detected through Server Header.", SCRIPT_NAME)
                binarysec.version = string.sub(response.header.server, 11)
                binarysec.detected = true
                return
            end
            if response.header['x-binarysec-via'] or response.header['x-binarysec-nocache']then
                if not binarysec.detected then stdnse.print_debug("%s BinarySec detected through header.", SCRIPT_NAME) end
                binarysec.detected = true
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local profense
profense = {
    name = "Profense",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server ==  'Profense' then
                stdnse.print_debug("%s Profense detected through Server header.", SCRIPT_NAME)
                profense.detected = true
                return
            end
            for _, cookie in pairs(response.cookies) do
                if cookie.name == "PLBSID" then
                    stdnse.print_debug("%s Profense detected through cookies.", SCRIPT_NAME)
                    profense.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local netscaler
netscaler = {
    name = "Citrix Netscaler",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do

            -- TODO Check for other version detection possibilities
            -- based on fingerprint difference
            if response.header.via and string.find(response.header.via, 'NS-CACHE') then -- 
                stdnse.print_debug("%s Citrix Netscaler detected through Via Header.", SCRIPT_NAME)
                netscaler.version = string.sub(response.header.via, 10, 12)
                netscaler.detected = true
                return 
            end

            if response.header.cneonction == "close" or response.header.nncoection == "close" then
                if not netscaler.detected then stdnse.print_debug("%s Netscaler detected through Cneoction/nnCoection header.", SCRIPT_NAME) end
                netscaler.detected = true
            end
            
            -- TODO Does X-CLIENT-IP apply to Citrix Application Firewall too ?
            if response.header['x-client-ip'] then
                if not netscaler.detected then stdnse.print_debug("%s Netscaler detected through X-CLIENT-IP header.", SCRIPT_NAME) end
                netscaler.detected = true
            end

            for _, cookie in pairs(response.cookies) do
                if cookie.name == "ns_af" or cookie.name == "citrix_ns_id" or 
                                    string.find(cookie.name, "NSC_") then
                    if not netscaler.detected then stdnse.print_debug("%s Netscaler detected through cookies.", SCRIPT_NAME) end
                    netscaler.detected = true
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local dotdefender
dotdefender = {
    name = "dotDefender",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header['X-dotdefender-denied'] == "1" then
                stdnse.print_debug("%s dotDefender detected through X-dotDefender-denied header.", SCRIPT_NAME)
                dotdefender.detected = true
                return
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local ibmdatapower
ibmdatapower = {
    name = "IBM DataPower",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header['x-backside-transport'] then
                stdnse.print_debug("%s IBM DataPower detected through X-Backside-Transport header.", SCRIPT_NAME)
                ibmdatapower.detected = true
                return
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local cloudflare 
cloudflare = {
    name = "Cloudflare",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server ==  'cloudflare-nginx' then
                stdnse.print_debug("%s Cloudflare detected through Server header.", SCRIPT_NAME)
                cloudflare.detected = true
                return
            end
            for _, cookie in pairs(response.cookies) do
                if cookie.name == "__cfduid" then
                    stdnse.print_debug("%s Cloudflare detected through cookies.", SCRIPT_NAME)
                    cloudflare.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local incapsula
incapsula = {
    name = "Incapsula WAF",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            for _, cookie in pairs(response.cookies) do
                if string.find(cookie.name, 'incap_ses') or string.find(cookie.name, 'visid_incap') then
                    stdnse.print_debug("%s Incapsula WAF detected through cookies.", SCRIPT_NAME)
                    incapsula.detected = true
                    return
                end
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local uspses 
uspses = {
    name = "USP Secure Entry Server",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server ==  'Secure Entry Server' then
                stdnse.print_debug("%s USP-SES detected through Server header.", SCRIPT_NAME)
                uspses.detected = true
                return
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}

local ciscoacexml
ciscoacexml = {
    name = "Cisco ACE XML Gateway",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server ==  'ACE XML Gateway' then
                stdnse.print_debug("%s Cisco ACE XML Gateway detected through Server header.", SCRIPT_NAME)
                ciscoacexml.detected = true
                return
            end
        end
    end,
    intensive = function(host, port, root, responses)
    end,
}


local modsecurity
modsecurity = { 
    -- Credit to Brendan Coles
    name = "ModSecurity",
    detected = false,
    version = nil,

    match = function(responses)
        for _, response in pairs(responses) do
            if response.header.server and string.find(response.header.server, 'mod_security/') then
                stdnse.print_debug("%s Modsecurity detected through Server Header.", SCRIPT_NAME)
                local pos = string.find(response.header.server, 'mod_security/')
                modsecurity.version = string.sub(response.header.server, pos + 13, pos + 18)
                modsecurity.detected = true
                return
            end 

            if response.header.server and string.find(response.header.server, 'Mod_Security') then
                stdnse.print_debug("%s Modsecurity detected through Server Header.", SCRIPT_NAME)
                modsecurity.version = string.sub(response.header.server, 13, -9) 
                modsecurity.detected = true
                return
            end 

            -- The default SecServerSignature value is "NOYB" <= TODO For older versions, so we could
            -- probably do some version detection out of it.
            if response.header.server ==  'NOYB' then 
                stdnse.print_debug("%s modsecurity detected through Server header.", SCRIPT_NAME)
                modsecurity.detected = true
            end 
        end 
    end,
    intensive = function(host, port, root, responses)
    end,
}

local naxsi
naxsi = { 
    name = "Naxsi",
    detected = false,
    version = nil,

    match = function(responses)
    end,
    intensive = function(host, port, root, responses)
	-- Credit to Henri Doreau
	local response = http.get(host, port, root .. "?a=[") -- This shouldn't trigget the rules
	local response2 = http.get(host, port, root .. "?a=[[[]]]][[[]") -- This should trigger the score based rules

	if response.status ~= response2.status then
                stdnse.print_debug("%s Naxsi detected through intensive scan.", SCRIPT_NAME)
                naxsi.detected = true
	end
	return
    end,
}


local wafs = {
    -- WAFs that are commented out don't have reliable fingerprints
    --  with no false positives yet.
          
    bigip = bigip,
    webknight = webknight,
    isaserver = isaserver,
    airlock = airlock,
    barracuda = barracuda,
    denyall = denyall,
    f5trafficshield = f5trafficshield,
    teros = teros,
    binarysec = binarysec,
    profense = profense,
    netscaler = netscaler,
    dotdefender = dotdefender,
    ibmdatapower = ibmdatapower,
    cloudflare = cloudflare,
    incapsula = incapsula,
    uspses = uspses,
    ciscoacexml = ciscoacexml,
    modsecurity = modsecurity,
    naxsi = naxsi,
--  netcontinuum = netcontinuum,
--  secureiis = secureiis,
--  urlscan = urlscan,
--  beeware = beeware,
--  hyperguard = hyperguard,
--  websecurity = websecurity,
--  imperva = imperva,
--  ibmwas = ibmwas,
--  nevisProxy = nevisProxy,
--  genericwaf = genericwaf,
}


local send_requests = function(host, port, root)
    local requests, all, responses = {}, {}, {}
    
    local dirtraversal = "../../../etc/passwd"
    local cleanhtml = "<hellot>hello"
    local xssstring = "<script>alert(1)</script>"
    local cmdexe = "cmd.exe"

    -- Normal index
    all = http.pipeline_add(root, nil, all, "GET")
    table.insert(requests,"normal")

    -- Normal inexisting
    all = http.pipeline_add(root .. "asofKlj", nil, all, "GET")
    table.insert(requests,"inexisting")
    
    -- Invalid Method
    all = http.pipeline_add(root, nil, all, "ASDE")
    table.insert(requests,"invalidmethod")
    
    -- Directory traversal
    all = http.pipeline_add(root .. "?parameter=" .. dirtraversal, nil, all, "GET")
    table.insert(requests,"invalidmethod")
    
    -- Invalid Host
    all = http.pipeline_add(root , {header= {Host = "somerandomsite.com"}}, all, "GET")
    table.insert(requests,"invalidhost")
    
    --Clean HTML encoded
    all = http.pipeline_add(root .. "?parameter=" .. cleanhtml , nil, all, "GET")
    table.insert(requests,"cleanhtml")
    
    --Clean HTML
    all = http.pipeline_add(root .. "?parameter=" .. url.escape(cleanhtml), nil, all, "GET")
    table.insert(requests,"cleanhtmlencoded")

    -- XSS
    all = http.pipeline_add(root .. "?parameter=" .. xssstring, nil, all, "GET")
    table.insert(requests,"xss")
    
    -- XSS encoded
    all = http.pipeline_add(root .. "?parameter=" ..  url.escape(xssstring), nil, all, "GET")
    table.insert(requests,"xssencoded")
    
    -- cmdexe
    all = http.pipeline_add(root .. "?parameter=" .. cmdexe, nil, all, "GET")
    table.insert(requests,"cmdexe")

    
    -- send all requests
    local pipeline_responses = http.pipeline_go(host, port, all)
    if not pipeline_responses then
        stdnse.print_debug("%s No response from pipelined requests", SCRIPT_NAME)
        return nil
    end
    
    -- Associate responses with requests names
    for i, response in pairs(pipeline_responses) do
        responses[requests[i]] = response 
    end 
    
    return responses
end

action = function(host, port)
    local root = stdnse.get_script_args(SCRIPT_NAME .. '.root') or "/"
    local intensive = stdnse.get_script_args(SCRIPT_NAME .. '.intensive')
    local result = {"Detected WAF", {}}

    -- We send requests
    local responses = send_requests(host, port, root)
    if not responses then
        return nil
    end

    -- We iterate over wafs table passing the responses list to each function to analyze
    -- the presence of any fingerprints.
    for _, waf in pairs(wafs) do
        waf.match(responses)
	if intensive then waf.intensive(host, port, root, responses) end
        if waf.detected then
            if waf.version then
                table.insert(result[2], waf.name .. " version " .. waf.version)
            else
                table.insert(result[2], waf.name)
            end
        end
    end
    if #result[2] > 0 then
        return stdnse.format_output(true, result)
    end
end
