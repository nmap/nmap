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
--   local cookiejar = new CookieJar(<optional cookie table>)
--   cookiejar:set_no_cookie_overwrite(true)
--   
--   local response
--   response = cookiejar.get(host, port, path, options)
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
-- The library also has support for a number of arguments.
--
-- @args httpcookies.cookiejar the argument passes a cookiejar which will be used
-- as session cookies in the http calls. This argument will be parsed by http library.
---

local http = require "http"
local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"
_ENV = stdnse.module("httpcookies", stdnse.seeall)

local LIBRARY_NAME = "httpcookies"

--TODO:
--Incorporate options in the library.
--HttpOnly and Secure attribute to be added.

-- The Cookies Class
CookieJar = {
  
  -- creates a new instance of CookieJar
  -- @param cookies A table or string containing cookies 
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
  end,

  -- Parses the cookie and and splits it into its attributes if its a string.
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
            return false --Name has to be of type string
        end
          elseif(cookie_attribute == 'value') then
          if(type(cookie_attribute_value) ~= 'string') then
            return false
          end
          elseif(cookie_attribute == 'path') then
            if(type(cookie_attribute_value) ~= 'string') then
            return false
          end
        elseif(cookie_attribute == 'expires') then
          if(type(cookie_attribute_value) ~= 'string') then
            return false
          end
        elseif(cookie_attribute == 'max-age') then
          if(type(cookie_attribute_value) ~= 'string') then
            return false
          end
        elseif(cookie_attribute == 'domain') then
          if(type(cookie_attribute_value) ~= 'string') then
            return false
          end
        elseif(cookie_attribute == 'secure') then 
          if(type(cookie_attribute_value) ~= 'boolean') then
            return false
          end
        elseif(cookie_attribute == 'httponly') then
          if(type(cookie_attribute_value) ~= 'boolean') then
            return false
          end
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

  --Setting default values for the options
  o.options.no_cookie_overwrite = o.options.no_cookie_overwrite or false

  --- This function merges the cookies received in <code>response.cookies</code> 
  -- to the cookies that already exist in the options. 
  -- The merge is based on RFC 6265 and when a different cookie with same <code>
  -- name</code>, <code>path</code> and <code>domain</code> is received, it replaces
  -- the old cookie, else it gets appended at the end of <code>options.cookies</code table.
  -- @param response The response received from the server
  -- @param options The options table having previously received cookies.
  -- @return (What should be returned here?? We can return some status for sure or something? beacuse the cookies are already being appended in the class object)
  -- @see http.get
  merge_cookie_table = function(self, host, path, response.cookies)
    local flag = false
    for r_index,r_cookie in pairs(response.cookies) do
      local maxage = r_cookie['max-age']
      local expires = r_cookie.expires
      local cookie_path = r_cookie.path
      local domain = r_cookie.domain
      local secure = r_cookie.secure
      local httponly = r_cookie.httponly
      --MaxAge attribute has precedence over expires
      if(maxage <=0 ) then
        break
      end
      --Else, time of execution of script will probably be less than cookie life.
      if maxage == nil and expires ~= nil then 
        --parse the cookie date
        --compare it with the present date.
        local p="%a+, (%d+) (%a+) (%d+) (%d+):(%d+):(%d+) GMT"
        local day,month,year,hour,min,sec, offset
        day,month,year,hour,min,sec=expires:match(p)
        local MON={Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
        month=MON[month]
        local offset=os.time()-os.time(os.date("!*t"))
        local timestamp = os.time({day=day,month=month,year=year,hour=hour,min=min,sec=sec})+offset
        local current_timestamp = os.time()
        if current_timestamp > timestamp then--Cookie expires value is before current date
        break
      end
    end
    --Cookie has to be discarded if the cookie_path is not a prefix of request_path.
    if path ~=nil and cookie_path ~= nil and string.find(cookie_path, path) == nil then
      break
    end
    --Cookie has to be discarded if the domain string is not a suffix of the host.
    if host ~=nil and domain ~=nil and string.find(host, domain) == nil then
      break
    end
    
    for o_index,o_cookie in pairs(self.cookies) do
      flag = false
      if(r_cookie.name == o_cookie.name) then
        --We need to check if domain and path are equal.
        --Note:If both domain and path are nil for r_cookie and o_cookie,
        --we need to change the cookie value 
        --See RFC 6265 Section 5.3 for how duplicate cookies are handled
        if(r_cookie.domain == o_cookie.domain and r_cookie.path == o_cookie.path and no_cookie_overwrite == false) then 
          self.cookies[o_index].value = response.cookies[r_index].value
          flag = true
          break
        end
      end 
    end
    if (flag == false) then
      self.cookies[#self.cookies+1] = response.cookies[r_index]
    end
  end
    response.cookies = self.cookies
    return response.cookies 
  end,

  -- Sets the no_cookie_overwrite used by the httpcookies library
  -- @param no_cookie_overwrite A boolean value for setting the option in library/
  set_no_cookie_overwrite = function(self, no_cookie_overwrite)
    self.options.no_cookie_overwrite = no_cookie_overwrite
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
    response = http.get(host, port, path, options)
    if response and response.status == 200 then 
      response = self.merge_cookie_table(host, path, response)
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
    respose = http.post(host, port, path, options, ignored, postdata)
    if response and response.status == 200 then
      response = self.merge_cookie_table(host, path, response)
    end
    return response
  end,

  ---This function servers as an easy method to add cookies to the existing cookie jar.
  --We can use this function to add arbitary cookie attributes with ease from our scripts
  --@param cookie_table A cookie table to be added to existing cookies. 
  add_cookie = function(self, cookie_table)
    local status
    status = self.parse(cookie_table)
    if status then 
      self.merge_cookie_table(nil, nil, cookie_table)
      return true
    return false
   end,

  --This function can be used to update a cookie with a different value.
  --@param cookie_table A cookie table where cookie_table.name matches the name of the cookie the 
  --value of which has to be updated. 
  update_cookie = function(self, cookie_table)
    local status
    status = self.parse(cookie_table)
    if status then
      self.merge_cookie_table(nil, nil, cookie_table)
      return true
    return false
  end,

  --This function can be used to delete a particular cookie from the cookie jar.
  --@param cookie_name A cookie name which has to be deleted from the cookie jar. 
  delete_cookie = function (self, cookie_name)
    for index, cookie in self.cookies do
      if cookie.name == cookie_name then
        self.cookies[index] = nil
        return true
      end
    end
    return false
  end,

  --This function can be used to get the value of the cookie 
  --@param status If cookie is found, true is returned
  --@param cookie_name A cookie table for which the value will be returned. 
  get_cookie = function (self, cookie_name)
    for index, cookie in self.cookies do
      if cookie.name == cookie_name then
        return true, self.cookies[index]
      end
    end
    return false
  end,

}

return _ENV;

 