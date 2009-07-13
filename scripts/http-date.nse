description = [[
Gets the date from HTTP-like services. Also prints how much the date
differs from local time. Local time is the time the HTTP request was
sent, so the difference includes at least the duration of one RTT.
]]

---
-- @output
-- 80/tcp open  http
-- |_ http-date: Mon, 13 Jul 2009 20:53:46 GMT; -5s from local time.

author = "David Fifield <david@bamsoftware.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require("http")
require("shortport")

portrule = shortport.port_or_service({80, 443, 631, 8080},
	{"http", "https", "ipp", "http-alt"})

-- Turn a positive or negative number of seconds into a string in one of the
-- forms:
-- 0s
-- +2s
-- -4s
-- +02m38s
-- -9h12m34s
-- 5d17h05m06s
local function format_difftime(t)
	local s, sign, sec

	if t > 0 then
		sign = "+"
	elseif t < 0 then
		sign = "-"
	else
		sign = ""
	end
	t = math.abs(t)

	-- Seconds.
	sec = t % 60
	s = string.format("%gs", sec)
	t = math.floor(t / 60)
	if t == 0 then return sign .. s end
	-- Minutes.
	s = string.format("%02dm%02ds", t % 60, sec)
	t = math.floor(t / 60)
	if t == 0 then return sign .. s end
	-- Hours.
	s = string.format("%dh", t % 24) .. s
	t = math.floor(t / 24)
	if t == 0 then return sign .. s end
	-- Days.
	s = string.format("%dd", t) .. s
	return sign .. s
end

action = function(host, port)
	-- Get local time in UTC.
	local request_time = os.time(os.date("!*t"))
	local response = http.get(host, port, "/")
	if not response.status or not response.header["date"] then
		return
	end

	local date = http.parse_date(response.header["date"])
	if not date then
		return
	end

	-- Should account for estimated RTT too.
	local diff = os.difftime(os.time(date), request_time)

	return string.format("%s; %s from local time.",
		response.header["date"], format_difftime(diff))
end
