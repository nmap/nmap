local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Exposes the admin login page in any website.
Displays both the user login and admin login pages in any website.

TODO:
- Automatically crawl the website and find the extension instead of taking
  it as a parameter from the user.
    - httpspider library can be used to accomplish this task.
- If there are frequent socket errors or http.request TIMEOUTS notify the user
  to check his internet connection and proxy instead of returning nil.
- Current database are having only 150 entries for each extension, updating this
  is a never ending process and this can be done frequently to obtain better results.
]]

---
--  @usage ./nmap --script login-page <target> -d
--  @usage ./nmap --script login-page --script-args extension="php" <target> -d
--
--  If timeout occurs frequently due to bad internet connection then
--  @usage ./nmap --script login-page --script-args extension="php" <target> --host-timeout=<timeout> -d
--
--  Best way to run the script
--  If the user has prior knowledge on which port to check, he can save time by
--  specifying that particular port as a general command line argument using -p
--  @usage ./nmap --script login-page --script-args extension="jsp" <target> -p 80 -d
--
--  @args login-page.extension Checks for pages of particular extension,
--        default is extension is all which checks for all the extensions.
--
--  @output
--  PORT   STATE SERVICE REASON
--  22/tcp open  ssh     syn-ack ttl 64
--  80/tcp open  http    syn-ack ttl 64
--  | login-page:
--  |   192.168.146.145/admin/
--  |   192.168.146.145/admin/index.php
--  |_  192.168.146.145/admin/login.php
---

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local append_data_to_table(tbl, data)
  local output = {}

  for _, val in pairs(tbl) do
    table.insert(output, val .. "." .. data)
  end

  return output
end

 -- This function concatenates the strings and tables (depth = 1) in
 -- a given table.
 --
 -- @param tbl A table is given as an input which contains values as string
 -- or table (depth = 1).
 -- @return Returns table after concatinating all the values.
local function concat_table_in_tables(tbl)

   local t = {}
   for _, v in ipairs(tbl) do
     if type(v) == "table" then
       for _, q in ipairs(v) do
         table.insert(t, q)
       end
     else
       table.insert(t, v)
     end
   end

   return t

 end

local function check_page(host, port, tbl)

  local hostname = host.targetname or host.ip

  local output = {}

  for _, uri in pairs(tbl) do
    stdnse.debug(string.format("Sending GET request to %s", hostname .. ':' .. port.number .. path .. uri))

    local response = http.get(host, port, path .. uri)

    for _, v in ipairs(regex) do
      if response.body ~= nil and string.match(response.body, v) then
        local url = hostname .. path .. uri
        -- Removing the non-alpha numeric strings if there exist any like \x0D
        local trimmed_url = url:gsub('\x0D','')
        table.insert(output, trimmed_url)
        break
      end
    end

  end

  return output

end

action = function(host, port)

  local path = "/"
  local extension = stdnse.get_script_args(SCRIPT_NAME .. ".extension") or "all"

  local extensions = {
    "aspx",
    "asp",
    "brf",
    "cgi",
    "cfm",
    "js",
    "jsp",
    "php",
    "all"
  }

  local var = {
    "acceso",
    "account",
    "adm/admloginuser",
    "adm",
    "adm_auth",
    "admin2",
    "admin2/index",
    "admin2/login",
    "admin/account",
    "admin/admin",
    "admin/admin_login",
    "admin/admin-login",
    "admin/adminLogin",
    "admin_area/admin",
    "adminarea/admin",
    "admin_area/index",
    "adminarea/index",
    "admin_area/login",
    "adminarea/login",
    "admin",
    "admincontrol",
    "admincontrol/login",
    "admin/controlpanel",
    "admin/cp",
    "admincp/index",
    "admincp/login",
    "adm/index",
    "admin/home",
    "admin/index",
    "administrator/account",
    "administrator",
    "administrator/index",
    "administrator/login",
    "administratorlogin",
    "admin_login",
    "admin-login",
    "admin/login",
    "adminLogin",
    "adminpanel",
    "admloginuser",
    "affiliate",
    "bb-admin/admin",
    "bb-admin/index",
    "bb-admin/login",
    "controlpanel",
    "cp",
    "home",
    "login",
    "memberadmin",
    "modelsearch/admin",
    "modelsearch/index",
    "modelsearch/login",
    "moderator/admin",
    "moderator",
    "moderator/login",
    "pages/admin/admin-login",
    "panel-administracion/admin",
    "panel-administracion/index",
    "panel-administracion/login",
    "siteadmin/index",
    "siteadmin/login",
    "user",
    "webadmin/admin",
    "webadmin",
    "webadmin/index",
    "webadmin/login",
  }

  local directories = {
    "adm/",
    "admin/",
    "admin1/",
    "admin2/",
    "admin3/",
    "admin4/",
    "admin5/",
    "admin_area/",
    "adminarea/",
    "administrator/",
    "administratorlogin/",
    "adminLogin/",
    "bb-admin/",
    "instadmin/",
    "memberadmin/",
    "moderator/",
    "panel-administracion/",
    "usuario/",
    "usuarios/",
    "webadmin/",
  }

  local htmlFiles = {
    "account.html",
    "adm.html",
    "admin/account.html",
    "admin/admin.html",
    "admin/admin_login.html",
    "admin/admin-login.html",
    "admin/adminLogin.html",
    "admin_area/admin.html",
    "adminarea/admin.html",
    "admin_area/index.html",
    "adminarea/index.html",
    "admin_area/login.html",
    "adminarea/login.html",
    "admincontrol.html",
    "admincontrol/login.html",
    "admin/controlpanel.html",
    "admin/cp.html",
    "admincp/index.html",
    "adm/index.html",
    "admin/home.html",
    "admin.html",
    "admin/index.html",
    "administrator/account.html",
    "administrator.html",
    "administrator/index.html",
    "administrator/login.html",
    "admin_login.html",
    "admin-login.html",
    "admin/login.html",
    "adminLogin.html",
    "adminpanel.html",
    "bb-admin/admin.html",
    "bb-admin/index.html",
    "bb-admin/login.html",
    "controlpanel.html",
    "cp.html",
    "home.html",
    "login.html",
    "modelsearch/admin.html",
    "modelsearch/index.html",
    "modelsearch/login.html",
    "moderator/admin.html",
    "moderator.html",
    "moderator/login.html",
    "pages/admin/admin-login.html",
    "panel-administracion/admin.html",
    "panel-administracion/index.html",
    "panel-administracion/login.html",
    "siteadmin/login.html",
    "user.html",
    "webadmin/admin.html",
    "webadmin.html",
    "webadmin/index.html",
    "webadmin/login.html",
  }

  extension = extension or "all"

  -- Raising an error if the extension provided by the user is not existing in our database.
  if not stdnse.contains(extensions, extension) then
    stdnse.debug("Invalid or missing extension.")
    return "Try executing script with --script-args extension."
  end

  -- Insensitive case regex for matching key words from the page
  local regex = {
    stdnse.generate_case_insensitive_pattern("username"), -- English (Username)
    stdnse.generate_case_insensitive_pattern("password"), -- English (Password)
    stdnse.generate_case_insensitive_pattern("p/w"), -- English (P/W)
    stdnse.generate_case_insensitive_pattern("admin password"), -- English (Admin Password)
    stdnse.generate_case_insensitive_pattern("personal"), -- English (Personal)
    stdnse.generate_case_insensitive_pattern("wachtwoord"), --Dutch (Password)
    stdnse.generate_case_insensitive_pattern("senha"), --Portuguese (Password)
    stdnse.generate_case_insensitive_pattern("clave"), --Spanish (Key)
    stdnse.generate_case_insensitive_pattern("usager"), --French (User)
  }

  local output = {}
  table.insert(output, check_page(directories))
  table.insert(output, check_page(htmlFiles))

  if extension == "all" then
    for _, ext in pairs(extensions) do
      table.insert(output, check_page(append_data_to_table(var, ext)))
    end
  else
    table.insert(output, check_page(append_data_to_table(var, extension)))
  end

  output = concat_table_in_tables(output)

  -- If the output table is empty return nil.
  if #output > 0 then
    return output
  else
    return nil
  end

end
