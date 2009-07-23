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

author = "David Fifield <david@bamsoftware.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require("http")
require("shortport")

portrule = shortport.port_or_service({80, 443, 631, 8080},
	{"http", "https", "ipp", "http-alt"})

local format_difftime

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
	local diff = format_difftime(response_date, request_date)

	return string.format("%s; %s from local time.",
		response.header["date"], diff)
end

-- Turn a positive or negative number of seconds into a string in one of the
-- forms. Signs can of course vary.
-- 0s
-- -4s
-- +2m38s
-- -9h12m34s
-- +5d17h05m06s
-- -2y177d10h13m20s
format_difftime = function(t2, t1)
	local d, s, sign, yeardiff

	d = os.difftime(os.time(t2), os.time(t1))
	if d > 0 then
		sign = "+"
	elseif d < 0 then
		sign = "-"
		t2, t1 = t1, t2
		d = -d
	else
		sign = ""
	end
	-- t2 is always later than or equal to t1 here.

	-- The year is a tricky case because it's not a fixed number of days
	-- the way a day is a fixed number of hours or an hour is a fixed
	-- number of minutes. For example, the difference between 2008-02-10
	-- and 2009-02-10 is 366 days because 2008 was a leap year, but it
	-- should be printed as 1y0d0h0m0s, not 1y1d0h0m0s. We advance t1 to be
	-- the latest year such that it is still before t2, which means that its
	-- year will be equal to or one less than t2's. The number of years
	-- skipped is stored in yeardiff.
	if t2.year > t1.year then
		local tmpyear = t1.year
		-- Put t1 in the same year as t2.
		t1.year = t2.year
		d = os.difftime(os.time(t2), os.time(t1))
		if d < 0 then
			-- Too far. Back off one year.
			t1.year = t2.year - 1
			d = os.difftime(os.time(t2), os.time(t1))
		end
		yeardiff = t1.year - tmpyear
		t1.year = tmpyear
	else
		yeardiff = 0
	end

	local s, sec, min
	s = ""
	-- Seconds (pad to two digits).
	sec = d % 60
	d = math.floor(d / 60)
	if d == 0 and yeardiff == 0 then
		return sign .. string.format("%gs", sec) .. s
	end
	s = string.format("%02gs", sec) .. s
	-- Minutes (pad to two digits).
	min = d % 60
	d = math.floor(d / 60)
	if d == 0 and yeardiff == 0 then
		return sign .. string.format("%dm", min) .. s
	end
	s = string.format("%02dm", min) .. s
	-- Hours.
	s = string.format("%dh", d % 24) .. s
	d = math.floor(d / 24)
	if d == 0 and yeardiff == 0 then
		return sign .. s
	end
	-- Days.
	s = string.format("%dd", d) .. s
	if yeardiff == 0 then return sign .. s end
	-- Years.
	s = string.format("%dy", yeardiff) .. s
	return sign .. s
end
