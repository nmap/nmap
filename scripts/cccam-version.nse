local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the CCcam service (software for sharing subscription TV among
multiple receivers).

The service normally runs on port 12000. It distinguishes
itself by printing 16 random-looking bytes upon receiving a
connection.

Because the script attempts to detect "random-looking" bytes, it has a small
chance of failing to detect the service when the data do not seem random
enough.]]

categories = {"version"}

author = "David Fifield"


-- A chi-square test for the null hypothesis that the members of data are drawn
-- from a uniform distribution over num_cats categories.
local function chi2(data, num_cats)
	local bins = {}
	local x2, delta, expected

	for _, x in ipairs(data) do
		bins[x] = bins[x] or 0
		bins[x] = bins[x] + 1
	end

	expected = #data / num_cats
	x2 = 0.0
	for _, n in pairs(bins) do
		delta = n - expected
		x2 = x2 + delta * delta
	end
	x2 = x2 / expected

	return x2
end

-- Split a string into a sequence of bit strings of the given length.
-- splitbits("abc", 5) --> {"01100", "00101", "10001", "00110"}
-- Any short final group is omitted.
local function splitbits(s, n)
	local seq

	local _, bits = bin.unpack("B" .. #s, s)
	seq = {}
	for i = 1, #bits - n, n do
		seq[#seq + 1] = bits:sub(i, i + n - 1)
	end

	return seq
end

-- chi-square cdf table at 0.95 confidence for different degrees of freedom.
-- >>> import scipy.stats, scipy.optimize
-- >>> scipy.optimize.newton(lambda x: scipy.stats.chi2(dof).cdf(x) - 0.95, dof)
local CHI2_CDF = {
	[3] = 7.8147279032511738,
	[15] = 24.99579013972863,
	[255] = 293.2478350807001,
}

local function looks_random(data)
	local x2

	-- Because our sample is so small (only 16 bytes), do a chi-square
	-- goodness of fit test across groups of 2, 4, and 8 bits. If using only
	-- 8 bits, for example, any sample whose bytes are all different would
	-- pass the test. Using 2 bits will tend to catch things like pure
	-- ASCII, where one out of every four samples never has its high bit
	-- set.

	x2 = chi2(splitbits(data, 2), 4)
	if x2 > CHI2_CDF[3] then
		return false
	end

	x2 = chi2(splitbits(data, 4), 16)
	if x2 > CHI2_CDF[15] then
		return false
	end

	x2 = chi2({string.byte(data, 1, -1)}, 256)
	if x2 > CHI2_CDF[255] then
		return false
	end

	return true
end

local NUM_TRIALS = 2

local function trial(host, port)
	local status, data, s

	s = nmap.new_socket()
	status, data = s:connect(host, port)
	if not status then
		return
	end

	status, data = s:receive_bytes(0)
	if not status then
		s:close()
		return
	end
	s:close()

	return data
end

portrule = shortport.version_port_or_service({10000, 10001, 12000, 12001, 16000, 16001}, "cccam")

function action(host, port)
	local seen = {}

	-- Try a couple of times to see that the response isn't constant. (But
	-- more trials also increase the chance that we will reject a legitimate
	-- cccam service.)
	for i = 1, NUM_TRIALS do
		local data

		data = trial(host, port)
		if not data or seen[data] or #data ~= 16 or not looks_random(data) then
			return
		end
		seen[data] = true
	end

	port.version.name = "cccam"
	port.version.version = "CCcam DVR card sharing system"
	nmap.set_port_version(host, port)
end
