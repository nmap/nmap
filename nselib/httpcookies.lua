---
-- The httpcookies library will provide a complete implementation of 
-- cookies. The library will prove useful to new scripts as we have 
-- an easy option to manage cookies. Existing scripts will be benefitted
-- by the library too as the arguments to the library can be easily
-- passed by scripts using http/httpspider library. The library will also 
-- be helpful in setting up arbitrary cookie values and sending it in the 
-- http requests which can prove to be quite useful in running scripts on
-- sites which authenticates through cookies. 
--
-- The library consists of the following class
--
-- * <code>CookieJar</code>
-- ** This is the main class which holds the cookie jar. 
--
-- The following sample code shows how the cookie jar could be used:
-- This code below will help us to pass cookies to the http calls, receive
-- further cookies and append them properly to the existing cookie jar.
-- 
-- <code>
--   local cookie_table = {}
--   table.insert(cookie_table, <optional cookie table>)
--   local cookiejar = httpcookies.CookieJar:new(cookie_table)
--   cookiejar:set_no_cookie_overwrite(true)
--   
--   local response
--   response = cookiejar:get(host, port, path, options)
--
--   return response
-- </code>
--
-- The following sample command tells us how to make use of the library
-- in the existing scripts :
-- 
-- $nmap --script http-xss-scanner --script-args httpcookies.cookiejar={<table of cookies>}
-- 
-- Using the above command, the http library will parse httpcookies arguments 
-- and makes an object of cookiejar class. This will help us to browse through
-- the pages with session cookies. Besides, it also merges the newly received 
-- cookies with the existing cookie jar.
--
-- The library supports an options table which provides the following functionlity
-- * <code>no_cookie_overwrite</code>: With this option set as true, if we receive another
-- cookie with the same name and attributes, the previous cookie wont be updated. (default:false)
--
-- @author Paulino Calderon <calderon@websec.mx>
-- @author Vinamra Bhatia 
--
---

local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"
local shortport  = require "shortport"
local http = require "http"

_ENV = stdnse.module("httpcookies", stdnse.seeall)

local LIBRARY_NAME = "httpcookies"

--TODO:
--Incorporate more options in the library.

-- The Cookies Class
CookieJar = {

  -- creates a new instance of CookieJar
  -- @param cookies A table or string containing cookies 
  -- @param options A table containing various options for the library.
  -- @return o new instance of CookieJar
  new = function(self, cookies, options)
    local o = {
      cookies = cookies or {},
      options = options or {},
    }

    setmetatable(o, self)
    self.__index = self

    if ( o:parse(self.cookies) ) then
      return o
    end

    --Setting default values for the options
  o.options.no_cookie_overwrite = o.options.no_cookie_overwrite or false 

  end,


  --- Parses the cookie and and splits it into its attributes if its a string.
  -- @param cookies A cookie table 
  -- @return status true on success, false on failure
  parse = function(cookies)
    if cookies == nil then
      return true
    end
    if (type(cookies) == 'table') then
      --Name and Value must be present in the cookie, rest
      --attributes are optional.
      --So, if we have a table of cookies, we take the first table 
      --and then loop for all the attributes in that table.
      for _,cookie in ipairs(cookies) do
        for cookie_attribute, cookie_attribute_value in pairs(cookie) do
          cookie_attribute = cookie_attribute:lower()
          if(cookie_attribute == 'name') then 
          if(type(cookie_attribute_value) ~= 'string') then
            stdnse.debug1("Cookie name is not a string")
            return false --Name has to be of type string
        end
          elseif(cookie_attribute == 'value') then
          if(type(cookie_attribute_value) ~= 'string') then
            stdnse.debug1("Cookie value is not a string")
            return false
          end
          elseif(cookie_attribute == 'path') then
            if(type(cookie_attribute_value) ~= 'string') then
              stdnse.debug1("Cookie path is not a string")  
            return false
          end
        elseif(cookie_attribute == 'expires') then
          if(type(cookie_attribute_value) ~= 'string') then
            stdnse.debug1("Cookie expires attribute is not a string") 
            return false
          end
        elseif(cookie_attribute == 'max-age') then
          if(type(cookie_attribute_value) ~= 'string') then
            stdnse.debug1("Cookie max-age attribute is not a string") 
            return false
          end
        elseif(cookie_attribute == 'domain') then
          if(type(cookie_attribute_value) ~= 'string') then
            stdnse.debug1("Cookie domain attribute is not a string")  
            return false
          end
        elseif(cookie_attribute == 'secure') then 
          if(type(cookie_attribute_value) ~= 'boolean') then
            stdnse.debug1("Cookie secure attribute is not a boolean")
            return false
          end
        elseif(cookie_attribute == 'httponly') then
          if(type(cookie_attribute_value) ~= 'boolean') then
            stdnse.debug1("Cookie httponly attribute is not a boolean")
            return false
          end
        else 
          stdnse.debug1("Cookie attribute is not recognised")
          return false
        end
      end
    end 
    return true
  elseif (type(cookies) == 'string') then 
      --We can parse it using the http parse cookie function
      cookies, status = http.parse_set_cookie(cookies)
      --Does it make sense to have multiple cookies parsed when we are using a string argument(?)
      if cookies == nil then
        return false
      end
      return true, cookies
    else
      return false--A cookie can only be string or table
    end
  end,

  --- This function merges the cookies received in <code>response.cookies</code> 
  -- to the cookies that already exist in the options. 
  -- The merge is based on RFC 6265 and when a different cookie with same <code>
  -- name</code>, <code>path</code> and <code>domain</code> is received, it replaces
  -- the old cookie, else it gets appended at the end of <code>options.cookies</code table.
  -- @param host Host table
  -- @param port Port table
  -- @param path Path
  -- @param cookies The cookies table to be appended in <code>self.cookies</code>
  -- @return cookies The complete cookie table having new cookies appended
  merge_cookie_table = function(self, host, port, path, cookies)
    local flag = false
    for r_index,r_cookie in pairs(cookies) do
      local maxage = r_cookie['max-age']
      local expires = r_cookie.expires
      local cookie_path = r_cookie.path
      local domain = r_cookie.domain
      local secure = r_cookie.secure 
      local httponly = r_cookie.httponly
      --MaxAge attribute has precedence over expires
      if(maxage ~=nil and maxage <=0 ) then
        stdnse.debug1("%s cookie has Max-age less than zero", r_cookie.name)
        break
      end
      --Else, time of execution of script will probably be less than cookie life.
      if maxage == nil and expires ~= nil then 
        --parse the cookie date
        --compare it with the present date.
        local p="%a+, (%d+)-(%a+)-(%d+) (%d+):(%d+):(%d+) GMT"
        local day,month,year,hour,min,sec,offset
        day,month,year,hour,min,sec=expires:match(p)
        local MON={Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
        month=MON[month]
        local offset=os.time()-os.time(os.date("!*t"))
        local timestamp = os.time({day=day,month=month,year=year,hour=hour,min=min,sec=sec})+offset
        local current_timestamp = os.time()
        if current_timestamp > timestamp then--Cookie expires value is before current date
          stdnse.debug1("%s cookie is expired", r_cookie.name)
        break
      end
    end
    --Cookie has to be discarded if the cookie_path is not a prefix of request_path.
    if path ~=nil and cookie_path ~= nil and string.find(cookie_path, path) == nil then
      stdnse.debug1("%s cookie doesnt match the path attribute", r_cookie.name)
      break
    end
    --Cookie has to be discarded if the domain string is not a suffix of the host.
    if host ~=nil and domain ~=nil and string.find(host, domain) == nil then
      stdnse.debug1("%s cookie doesnt match the domain attribute", r_cookie.name)
      break
    end
    --Cookie has to be discarded if its not a secure connection and secure flag is set.
    if secure ~= nil and secure == true and shortport.ssl(host,port) == false then
      stdnse.debug1("%s cookie doesnt match the secure attribute", r_cookie.name)
      break
    end
    --Cookie has to be discarded if its not http request and httponly is set
    if httponly ~= nil and httponly == true and shortport.http(host,port) == false then
      stdnse.debug1("%s cookie doesnt match the httponly attribute", r_cookie.name)
      break
    end
    for o_index,o_cookie in pairs(self.cookies) do
      flag = false
      if(r_cookie.name == o_cookie.name) then
        --We need to check if domain and path are equal.
        --Note:If both domain and path are nil for r_cookie and o_cookie,
        --we need to change the cookie value 
        --See RFC 6265 Section 5.3 for how duplicate cookies are handled
        if(r_cookie.domain == o_cookie.domain and r_cookie.path == o_cookie.path and self.options.no_cookie_overwrite == false) then 
          self.cookies[o_index].value = cookies[r_index].value
          flag = true
          break
        end
      end 
    end
    if (flag == false) then
      self.cookies[#self.cookies+1] = cookies[r_index]
    end
  end
  cookies = self.cookies
  return cookies 
  end,

  -- Sets the no_cookie_overwrite used by the httpcookies library
  -- @param no_cookie_overwrite A boolean value for setting the option in library/
  set_no_cookie_overwrite = function(self, no_cookie_overwrite)
    self.options.no_cookie_overwrite = no_cookie_overwrite or false
  end,

  ---This function calls the http.get. It then parses the 
  --cookies and merges them with the previously stored cookies.
  --Several options can alter the behavior of the cookies library.
  --@param host Host table
  --@param port Port table
  --@param path Path
  --@param options Options table containing various options.
  --@return Response Table with the previous cookies appended as well
  get = function(self, host, port, path, options)
    local response
    --Here, the cookies present in the object will automatically be taken 
    if options == nil then options = {} end
    options.cookies = self.cookies
    response = http.get(host, port, path, options)
    if response and response.status == 200 and response.cookies then 
      response.cookies = self.merge_cookie_table(self, host, port, path, response.cookies)
    end 
    return response
  end,

  ---This function calls the http.post. It then parses the 
  --cookies and merges them with the previously stored cookies.
  --Several options can alter the behavior of the cookies library.
  --@param host Host table
  --@param port Port table
  --@param path Path
  --@param options Options table containing various options.
  --@return Response Table with the previous cookies appended as well
  post = function(self, host, port, path, options, ignored, postdata)
    local response
    --Here, the cookies present in the object will automatically be taken 
    if options == nil then options = {} end
    options.cookies = self.cookies
    respose = http.post(host, port, path, options, ignored, postdata)
    if response and response.status == 200 and response.cookies then
      response.cookies = self.merge_cookie_table(self, host, port, path, response.cookies)
    end
    return response
  end,

  ---This function servers as an easy method to add cookies to the existing cookie jar.
  --We can use this function to add arbitary cookie attributes with ease from our scripts
  --@param cookie_table A cookie table to be added to existing cookies. 
  add_cookie = function(self, cookie_table)
    local status
    status = self.parse(cookie_table)
    local cookies = {}
    table.insert(cookies, cookie_table)
    if status then 
      self.merge_cookie_table(self, nil, nil, nil, cookies)
      return true
    end
    return false
   end,

  ---This function can be used to update a cookie with a different value.
  --@param cookie_table A cookie table where cookie_table.name matches the name of the cookie the 
  --value of which has to be updated. 
  --@return status Returns true if cookie is present and successfully removed.
  update_cookie = function(self, cookie_table)
    local status
    status = self.parse(cookie_table)
    if status == false then
      return false
    end
    for index, cookie in pairs(self.cookies) do
      if cookie.name == cookie_table.name then
        self.cookies[index] = cookie_table
        return true
      end
    end
    return false
  end,

  ---This function can be used to delete a particular cookie from the cookie jar.
  --@param cookie_name A cookie name which has to be deleted from the cookie jar. 
  --@return status Returns true if cookie is present and successfully removed.
  delete_cookie = function (self, cookie_name)
    for index, cookie in pairs(self.cookies) do
      if cookie.name == cookie_name then
        self.cookies[index] = nil
        return true
      end
    end
    return false
  end,

  ---This function can be used to get the value of the cookie 
  --@param cookie_name A cookie table for which the value will be returned. 
  --@return status If cookie is found, true is returned
  get_cookie = function (self, cookie_name)
    for index, cookie in pairs(self.cookies) do 
      if cookie.name == cookie_name then
        return true, self.cookies[index]
      end
    end
    return false
  end,

}

return _ENV;

