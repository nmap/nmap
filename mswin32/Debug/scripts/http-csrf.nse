description = [[
This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.

It will try to detect them by checking each form if it contains an unpredictable
token for each user. Without one an attacker may forge malicious requests.

To recognize a token in a form, the script will iterate through the form's
attributes and will search for common patterns in their names. If that fails, it
will also calculate the entropy of each attribute's value. A big entropy means a
possible token.

A common use case for this script comes along with a cookie that gives access
in pages that require authentication, because that's where the privileged
exist. See the http library's documentation to set your own cookie.
]]

---
-- @usage nmap -p80 --script http-csrf.nse <target>
--
-- @args http-csrf.singlepages The pages that contain the forms to check.
--       For example, {/upload.php,  /login.php}. Default: nil (crawler
--       mode on)
-- @args http-csrf.checkentropy If this is set the script will also calculate
--       the entropy of the field's value to determine if it is a token,
--       rather than just checking its name. Default: true
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-csrf:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=some-very-random-page.com
-- |   Found the following CSRF vulnerabilities:
-- |
-- |     Path: http://www.example.com/
-- |     Form id: search_bar_input
-- |     Form action: /search
-- |
-- |     Path: http://www.example.com/c/334/watches.html
-- |     Form id: custom_price_filters
-- |     Form action: /search
-- |
-- |     Path: http://www.example.com/c/334/watches.html
-- |     Form id: custom_price_filters
-- |_    Form action: /c/334/rologia-xeiros-watches.html
--
---

categories = {"intrusive", "exploit", "vuln"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local formulas = require "formulas"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

-- Checks if this is really a token.
isToken = function(value)

  local minlength = 8
  local minentropy = 72

  -- If it has a reasonable length.
  if #value > minlength then

    local entropy = formulas.calcPwdEntropy(value)

    -- Does it have a big entropy?
    if entropy >= minentropy then
      -- If it doesn't contain any spaces but contains at least one digit.
      if not string.find(value, " ") and string.find(value, "%d") then
        return 1
      end
    end
  end

  return 0

end

action = function(host, port)

  local singlepages = stdnse.get_script_args("http-csrf.singlepages")
  local checkentropy = stdnse.get_script_args("http-csrf.checkentropy") or false

  local csrfvuln = {}
  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME, withinhost = 1 } )

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  local index, response, path
  while (true) do

    if singlepages then
      local k, target,
      k, target = next(singlepages, index)
      if (k == nil) then
        break
      end
      response = http.get(host, port, target)
      path = target

    else
      local status, r = crawler:crawl()
      -- if the crawler fails it can be due to a number of different reasons
      -- most of them are "legitimate" and should not be reason to abort
      if (not(status)) then
        if (r.err) then
          return stdnse.format_output(false, r.reason)
        else
          break
        end
      end

      response = r.response
      path = tostring(r.url)
    end

    if response.body then

      local forms = http.grab_forms(response.body)

      for i, form in ipairs(forms) do

        form = http.parse_form(form)

        local resistant = false
        if form and form.action then
          for _, field in ipairs(form['fields']) do

            -- First we check the field's name.
            if field['value'] then
              resistant = string.find(field['name'], "[Tt][Oo][Kk][Ee][Nn]") or string.find(field['name'], "[cC][sS][Rr][Ff]")
              -- Let's be sure, by calculating the entropy of the field's value.
              if not resistant and checkentropy then
                resistant = isToken(field['value'])
              end

              if resistant then
                break
              end
            end

          end

          if not resistant then

            -- Handle forms with no id or action attributes.
            form['id'] = form['id'] or ""
            form['action'] = form['action'] or "-"

            local msg = "\nPath: " .. path .. "\nForm id: " .. form['id'] .. "\nForm action: " .. form['action']
            table.insert(csrfvuln, { msg } )
          end
        end
      end

      if (index) then
        index = index + 1
      else
        index = 1
      end
    end

  end

  -- If the table is empty.
  if next(csrfvuln) == nil then
    return "Couldn't find any CSRF vulnerabilities."
  end

  table.insert(csrfvuln, 1, "Found the following possible CSRF vulnerabilities: ")

  csrfvuln.name = crawler:getLimitations()

  return stdnse.format_output(true, csrfvuln)

end
