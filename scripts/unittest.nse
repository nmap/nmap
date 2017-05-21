local stdnse = require "stdnse"
local unittest = require "unittest"

description = [[
Runs unit tests on all NSE libraries.
]]

---
-- @args unittest.run Run tests. Causes <code>unittest.testing()</code> to
--                    return true.
--
-- @args unittest.tests Run tests from only these libraries (defaults to all)
--
-- @usage
-- nmap --script unittest --script-args unittest.run
--
-- @output
-- Pre-scan script results:
-- | unittest:
-- |_ All tests passed

author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe"}


prerule = unittest.testing

action = function()
  local libs = stdnse.get_script_args("unittest.tests")
  local result
  if libs then
    result = unittest.run_tests(libs)
  else
    result = unittest.run_tests()
  end
  if #result == 0 then
    return "All tests passed"
  else
    return result
  end
end
