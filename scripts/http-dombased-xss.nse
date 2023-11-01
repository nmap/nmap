description = [[
This advanced NSE script scans for potential DOM-based XSS vulnerabilities in web applications, including HTML forms, JavaScript code, Java applets, and anchor (a) tags. The script uses advanced patterns and techniques to minimize false positives.
]]

---
-- @usage nmap -p80 --script http-advanced-domxss.nse <target>
--
-- This script aims to detect potential DOM-based XSS vulnerabilities in HTML forms, JavaScript code, Java applets, and anchor (a) tags using advanced patterns and techniques. While it reduces false positives, it's essential to review the results carefully.
--
-- @args http-advanced-domxss.singlepages The pages to test (e.g., {"/index.php", "/profile.php"}). Default: nil (crawler mode enabled)
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-advanced-domxss:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=some-very-random-page.com
-- |   Found the following indications of potential DOM-based XSS:
-- |
-- |     Source: <form action="vulnerable.php"><input name="input" value="+document.URL.substring(pos,document.URL.length)"></form>
-- |     Website: http://some-very-random-page.com:80
-- |     Port: 80
-- |     Parameter: input
-- |     Vulnerability: Potential DOM-based XSS
-- |     Request: GET /vulnerable.php?input=sample
-- |     Response: HTTP 200 OK
-- |_  
--
-- @see http-stored-xss.nse
-- @see http-phpself-xss.nse
-- @see http-xssed.nse
-- @see http-unsafe-output-escaping.nse
---

categories = {"intrusive", "exploit", "vuln"}
author = "Haroon Ahmad Awan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

DOM_VULNERABILITY_PATTERNS = {
    -- Patterns for detecting vulnerabilities in HTML forms
    '<form[^>]*>(.-)</form>', -- Capturing the content within form tags
    'action%s*=%s*"(.-)"', -- Capturing the action attribute within form tags
    '<input[^>]*>', -- Capturing input fields within forms

    -- Patterns for detecting vulnerabilities in JavaScript
    '<script[^>]*>(.-)</script>', -- Capturing the content within script tags

    -- Patterns for detecting vulnerabilities in Java applets
    '<applet[^>]*>(.-)</applet>', -- Capturing the content within applet tags

    -- Patterns for detecting vulnerabilities in anchor (a) tags
    '<a[^>]*>(.-)</a>', -- Capturing the content within anchor tags
    'href="(.-)"', -- Capturing the href attribute within anchor tags
}

JS_FUNC_PATTERNS = {
    '(document%.write%s*%((.-)%))',
    '(document%.writeln%s*%((.-)%))',
    '(document%.execCommand%s*%((.-)%))',
    '(document%.open%s*%((.-)%))',
    '(window%.open%s*%((.-)%))',
    '(eval%s*%((.-)%))',
    '(window%.execScript%s*%((.-)%))',
}

JS_CALLS_PATTERNS = {
    'document%.URL',
    'document%.documentURI',
    'document%.URLUnencoded',
    'document%.baseURI',
    'document%.referrer',
    'location',
}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
    local singlepages = stdnse.get_script_args("http-advanced-domxss.singlepages")
    local domxss = {}
    local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME, withinhost = 1 })

    if not crawler then
        return
    end

    crawler:set_timeout(10000)

    local index, k, target, response, path
    while true do
        if singlepages then
            k, target = next(singlepages, index)
            if k == nil then
                break
            end
            response = http.get(host, port, target)
            path = target
        else
            local status, r = crawler:crawl()
            if not status then
                if r.err then
                    return stdnse.format_output(false, r.reason)
                else
                    break
                end
            end
            response = r.response
            path = tostring(r.url)
        end

        if response.body then
            for _, pattern in ipairs(DOM_VULNERABILITY_PATTERNS) do
                for match in string.gmatch(response.body, pattern) do
                    -- Analyze and validate the match for potential vulnerabilities
                    if IsPotentialDOMXSS(match) then
                        if not domxss[match] then
                            domxss[match] = { path }
                        else
                            table.insert(domxss[match], ", " .. path)
                        end
                    end
                end
            end
            if index then
                index = index + 1
            else
                index = 1
            end
        end
    end

    if next(domxss) == nil then
        return "No potential DOM-based XSS vulnerabilities found."
    end

    local results = {}
    for x, _ in pairs(domxss) do
        table.insert(results, {
            "Source: " .. x,
            "Website: " .. host.ip .. ":" .. port.number,
            "Port: " .. port.number,
            "Parameter: N/A",
            "Vulnerability: Potential DOM-based XSS",
            "Request: N/A",
            "Response: N/A"
        })
    end

    results.name = crawler:getLimitations()

    return stdnse.format_output(true, results)
end

-- Validate and filter potential DOM-based XSS matches to reduce false positives
function IsPotentialDOMXSS(match)
    -- List of patterns to identify potential DOM-based XSS
    local patterns = {
        DOM_VULNERABILITY_PATTERNS, -- Your existing patterns
        JS_FUNC_PATTERNS, -- Additional JavaScript function patterns
        JS_CALLS_PATTERNS, -- Additional JavaScript call patterns
    }

    -- Check if any of the patterns match the input
    for _, patternSet in ipairs(patterns) do
        for _, pattern in ipairs(patternSet) do
            if string.match(match, pattern) then
                return true -- Return true if any pattern matches
            end
        end
    end

    return false -- No patterns matched; it's not a potential vulnerability
end

-- Optionally capture the request and response for detected vulnerabilities
function CaptureRequestAndResponse(host, port, path)
  local request = "N/A"
  local response = "N/A"

  -- Use http library to capture request and response details
  local result = http.get(host, port, path)

  if result then
    if result.request then
      request = result.request
    end

    if result.response then
      response = result.response
    end
  end

  return request, response
end
