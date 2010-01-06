description = [[
Gets the date from HTTP-like services. Also prints how much the date
differs from local time. Local time is the time the HTTP request was
sent, so the difference includes at least the duration of one RTT.
]]

---
-- @output
-- 80/tcp open  http
-- |_ http-date: Thu, 23 Jul 2009 23:15:57 GMT; -6s from local time.
-- 80/tcp open  http
-- |_ http-date: Wed, 17 Jan 2007 09:29:10 GMT; -2y187d13h46m53s from local time.

author = "David Fifield"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require("http")
require("shortport")
require("stdnse")

portrule = shortport.port_or_service({80, 443, 631, 8080},
	{"http", "https", "ipp", "http-alt"})

action = function(host, port)
	-- Get the local date in UTC.
	local request_date = os.date("!*t")
	local response = http.get(host, port, "/")
	if not response.status or not response.header["date"] then
		return
	end

	local response_date = http.parse_date(response.header["date"])
	if not response_date then
		return
	end

	-- Should account for estimated RTT too.
	local diff = stdnse.format_difftime(response_date, request_date)

	return string.format("%s; %s from local time.",
		response.header["date"], diff)
end
