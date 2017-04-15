local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exposes the admin login page in any website.
Displays both the user login and admin login pages in all websites.
]]
