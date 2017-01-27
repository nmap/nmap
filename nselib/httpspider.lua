---
-- A smallish httpspider library providing basic spidering capabilities
-- It consists of the following classes:
--
-- * <code>Options</code>
-- ** This class is responsible for handling library options.
--
-- * <code>LinkExtractor</code>
-- ** This class contains code responsible for extracting urls from web pages.
--
-- * <code>URL</code>
-- ** This class contains code to parse and process URLs.
--
-- * <code>UrlQueue</code>
-- ** This class contains a queue of the next links to process.
--
-- * <code>Crawler</code>
-- ** This class is responsible for the actual crawling.
--
-- The following sample code shows how the spider could be used:
-- <code>
--   local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME } )
--   crawler:set_timeout(10000)
--
--   local result
--   while(true) do
--     local status, r = crawler:crawl()
--     if ( not(status) ) then
--       break
--     end
--     if ( r.response.body:match(str_match) ) then
--        crawler:stop()
--        result = r.url
--        break
--     end
--   end
--
--   return result
-- </code>
--
-- For advanced use, the library currently supports a number of closures (withinhost,
-- withindomain, doscraping). Please note, that withinhost and withindomain options also
-- support boolean values. You will want to override them only for advanced use. You can
-- define them using the following utilities:
--
-- * <code>iswithinhost</code>
-- ** You can use this utility to check if the resource exists within the host.
--
-- * <code>iswithindomain</code>
-- ** You can use this utility to check if the resource exists within the domain.
--
-- * <code>isresource</code>
-- ** You can use this utility to check the type of the resource (for example "js").
-- ** A third option may hold a number of signs that may exist after the extension
-- ** of the resource. By default, these are [#, ?]. For example, if we want to return
-- only php resources, the function will also return example.php?query=foo or
-- example.php#foo.
--
-- The following sample code shows an example usage. We override the default
-- withinhost method and we allow spidering only on resources within the host
-- that they are not "js" or "css".
-- <code>
--   crawler.options.withinhost = function(url)
--       if crawler:iswithinhost(url)
--       and not crawler:isresource(url, "js")
--       and not crawler:isresource(url, "css") then
--           return true
--       end
--    end
-- </code>
--
-- @author Patrik Karlsson <patrik@cqure.net>
--
-- @args httpspider.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args httpspider.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args httpspider.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args httpspider.withinhost Closure that overrides the default withinhost
--       function that only spiders URLs within the same host. If this is
--       set to false the crawler will spider URLs both inside and outside
--       the host. See the closure section above to override the default
--       behaviour. (default: true)
-- @args httpspider.withindomain Closure that overrides the default
--       withindomain function that only spiders URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. See the closure section above to
--       override the default behaviour. (default: false)
-- @args httpspider.noblacklist if set, doesn't load the default blacklist
-- @args httpspider.useheadfornonwebfiles if set, the crawler would use
--       HEAD instead of GET for files that do not have extensions indicating
--       that they are webpages (the list of webpage extensions is located in
--       nselib/data/http-web-files-extensions.lst)
-- @args httpspider.doscraping Closure that overrides the default doscraping
--       function used to check if the resource should be scraped (in terms
--       of extracting any links within it). See the closure section above to
--       override the default behaviour.
---

local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
_ENV = stdnse.module("httpspider", stdnse.seeall)

local LIBRARY_NAME = "httpspider"
local PREFETCH_SIZE = 5

-- The Options class, handling all spidering options
Options = {

  new = function(self, options)
    local o = { }

    -- copy all options as class members
    for k, v in pairs(options) do o[k] = v  end

    -- set a few default values
    o.timeout  = options.timeout or 10000
    o.whitelist = o.whitelist or {}
    o.blacklist = o.blacklist or {}
    local removewww = function(url) return string.gsub(url, "^www%.", "") end

    -- set up the appropriate matching functions
    if ( o.withinhost ) then
      o.withinhost = function(u)
        local parsed_u = url.parse(tostring(u))

        if ( o.base_url:getPort() ~= 80 and o.base_url:getPort() ~= 443 ) then
          if ( tonumber(parsed_u.port) ~= tonumber(o.base_url:getPort()) ) then
            return false
          end
        elseif ( parsed_u.scheme ~= o.base_url:getProto() ) then
          return false
          -- if urls don't match only on the "www" prefix, then they are probably the same
        elseif ( parsed_u.host == nil or removewww(parsed_u.host:lower()) ~= removewww(o.base_url:getHost():lower()) ) then
          return false
        end
        return true
      end
    end
    if ( o.withindomain ) then
      o.withindomain = function(u)
        local parsed_u = url.parse(tostring(u))
        if ( o.base_url:getPort() ~= 80 and o.base_url:getPort() ~= 443 ) then
          if ( tonumber(parsed_u.port) ~= tonumber(o.base_url:getPort()) ) then
            return false
          end
        elseif ( parsed_u.scheme ~= o.base_url:getProto() ) then
          return false
        elseif ( parsed_u.host == nil or parsed_u.host:sub(-#o.base_url:getDomain()):lower() ~= o.base_url:getDomain():lower() ) then
          return false
        end
        return true
      end
    end

    if (not o.doscraping) then

      o.doscraping = function(u)
        return true
      end
    end

    setmetatable(o, self)
    self.__index = self
    return o
  end,

  addWhitelist = function(self, func) table.insert(self.whitelist, func) end,
  addBlacklist = function(self, func) table.insert(self.blacklist, func) end,

}

-- Placeholder for form extraction code
FormExtractor = {

}

LinkExtractor = {

  -- Creates a new instance of LinkExtractor
  -- @return o instance of LinkExtractor
  new = function(self, url, html, options)
    local o = {
      url = url,
      html = html,
      links = {},
      options = options,
    }
    setmetatable(o, self)
    self.__index = self
    o:parse()

    return o
  end,

  -- is the link absolute or not?
  isAbsolute = function(url)
    -- at this point we don't care about the protocol
    -- also, we don't add // to cover stuff like:
    -- feed:http://example.com/rss.xml
    return ( url:match('^%w*:') ~= nil )
  end,

  -- Creates an absolute link from a relative one based on the base_url
  -- The functionality is very simple and does not take any ../../ in
  -- consideration.
  --
  -- @param base_url URL containing the page url from which the links were
  --        extracted
  -- @param rel_url string containing the relative portion of the URL
  -- @return link string containing the absolute link
  createAbsolute = function(base_url, rel_url, base_href)

    -- is protocol-relative?
    if rel_url:match("^//") then
      return ("%s%s%s"):format(base_url:getProto(), ":", rel_url)
    end

    -- is relative with leading slash? ie /dir1/foo.html
    local leading_slash = rel_url:match("^/")
    rel_url = rel_url:match("^/?(.*)") or '/'

    -- check for tailing slash
    if ( base_href and not(base_href:match("/$") ) ) then
      base_href = base_href .. '/'
    end

    if ( ( base_url:getProto() == 'https' and base_url:getPort() == 443 ) or
        ( base_url:getProto() == 'http' and base_url:getPort() == 80 ) ) then

      if ( leading_slash ) then
        return ("%s://%s/%s"):format(base_url:getProto(), base_url:getHost(), rel_url)
      else
        if ( base_href ) then
          return ("%s%s"):format(base_href, rel_url)
        else
          return ("%s://%s%s%s"):format(base_url:getProto(), base_url:getHost(), base_url:getDir(), rel_url)
        end
      end
    else
      if ( leading_slash ) then
        return ("%s://%s:%d/%s"):format(base_url:getProto(), base_url:getHost(), base_url:getPort(), rel_url)
      else
        if ( base_href ) then
          return ("%s%s"):format(base_href, rel_url)
        else
          return ("%s://%s:%d%s%s"):format(base_url:getProto(), base_url:getHost(), base_href or base_url:getPort(), base_url:getDir(), rel_url)
        end
      end
    end
  end,

  -- Gets the depth of the link, relative to our base url eg.
  -- base_url = http://www.cqure.net/wp/
  -- url = http://www.cqure.net/wp/                           - depth: 0
  -- url = http://www.cqure.net/wp/index.php                  - depth: 0
  -- url = http://www.cqure.net/wp/2011/index.php             - depth: 1
  -- url = http://www.cqure.net/index.html                    - depth: -1
  --
  -- @param url instance of URL
  -- @return depth number containing the depth relative to the base_url
  getDepth = function(self, url)
    local base_dir, url_dir = self.options.base_url:getDir(), url:getDir()
    if ( url_dir and base_dir ) then
      local m = url_dir:match(base_dir.."(.*)")
      if ( not(m) ) then
        return -1
      else
        local _, depth = m:gsub("/", "/")
        return depth
      end
    end
  end,

  validate_link = function(self, url)
    local valid = true

    -- if our url is nil, abort, this could be due to a number of
    -- reasons such as unsupported protocols: javascript, mail ... or
    -- that the URL failed to parse for some reason
    if ( url == nil or tostring(url) == nil ) then
      return false
    end

    -- linkdepth trumps whitelisting
    if ( self.options.maxdepth and self.options.maxdepth >= 0 ) then
      local depth = self:getDepth( url )
      if ( -1 == depth or depth > self.options.maxdepth ) then
        stdnse.debug3("%s: Skipping link depth: %d; b_url=%s; url=%s", LIBRARY_NAME, depth, tostring(self.options.base_url), tostring(url))
        return false
      end
    end

    -- withindomain trumps any whitelisting
    if ( self.options.withindomain ) then
      if ( not(self.options.withindomain(url)) ) then
        stdnse.debug2("%s: Link is not within domain: %s", LIBRARY_NAME, tostring(url))
        return false
      end
    end

    -- withinhost trumps any whitelisting
    if ( self.options.withinhost ) then
      if ( not(self.options.withinhost(url)) ) then
        stdnse.debug2("%s: Link is not within host: %s", LIBRARY_NAME, tostring(url))
        return false
      end
    end

    -- run through all blacklists
    if ( #self.options.blacklist > 0 ) then
      for _, func in ipairs(self.options.blacklist) do
        if ( func(url) ) then
          stdnse.debug2("%s: Blacklist match: %s", LIBRARY_NAME, tostring(url))
          valid = false
          break
        end
      end
    end

    -- check the url against our whitelist
    if ( #self.options.whitelist > 0 ) then
      valid = false
      for _, func in ipairs(self.options.whitelist) do
        if ( func(url) ) then
          stdnse.debug2("%s: Whitelist match: %s", LIBRARY_NAME, tostring(url))
          valid = true
          break
        end
      end
    end
    return valid
  end,

  -- Parses a HTML response and extracts all links it can find
  -- The function currently supports href, src and action links
  -- Also all behaviour options, such as depth, white- and black-list are
  -- processed in here.
  parse = function(self)
    local links = {}
    local patterns = {
      '[hH][rR][eE][fF]%s*=%s*[\'"]%s*([^"^\']-)%s*[\'"]',
      '[hH][rR][eE][fF]%s*=%s*([^\'\"][^%s>]+)',
      '[sS][rR][cC]%s*=%s*[\'"]%s*([^"^\']-)%s*[\'"]',
      '[sS][rR][cC]%s*=%s*([^\'\"][^%s>]+)',
      '[aA][cC][tT][iI][oO][nN]%s*=%s*[\'"]%s*([^"^\']+%s*)[\'"]',
    }

    local base_hrefs = {
      '[Bb][Aa][Ss][Ee]%s*[Hh][Rr][Ee][Ff]%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]',
      '[Bb][Aa][Ss][Ee]%s*[Hh][Rr][Ee][Ff]%s*=%s*([^\'\"][^%s>]+)'
    }

    local base_href
    for _, pattern in ipairs(base_hrefs) do
      base_href = self.html:match(pattern)
      if ( base_href ) then
        break
      end
    end

    for _, pattern in ipairs(patterns) do
      for l in self.html:gmatch(pattern) do
        local link = l
        if ( not(LinkExtractor.isAbsolute(l)) ) then
          link = LinkExtractor.createAbsolute(self.url, l, base_href)
        end

        local url = URL:new(link)

        local valid = self:validate_link(url)

        if ( valid ) then
          stdnse.debug3("%s: Adding link: %s", LIBRARY_NAME, tostring(url))
          links[tostring(url)] = true
        elseif ( tostring(url) ) then
          stdnse.debug3("%s: Skipping url: %s", LIBRARY_NAME, link)
        end
      end
    end

    for link in pairs(links) do
      table.insert(self.links, link)
    end

  end,

  -- Gets a table containing all of the retrieved URLs, after filtering
  -- has been applied.
  getLinks = function(self) return self.links end,


}

-- The URL class, containing code to process URLS
-- This class is heavily inspired by the Java URL class
URL = {

  -- Creates a new instance of URL
  -- @param url string containing the text representation of a URL
  -- @return o instance of URL, in case of parsing being successful
  --         nil in case parsing fails
  new = function(self, url)
    local o = {
      raw = url,
    }

    setmetatable(o, self)
    self.__index = self
    if ( o:parse() ) then
      return o
    end
  end,

  -- Parses the string representation of the URL and splits it into different
  -- URL components
  -- @return status true on success, false on failure
  parse = function(self)
    self.proto, self.host, self.port, self.file = self.raw:match("^(http[s]?)://([^:/]*)[:]?(%d*)")
    if ( self.proto and self.host ) then
      self.file = self.raw:match("^http[s]?://[^:/]*[:]?%d*(/[^#]*)") or '/'
      self.port = tonumber(self.port)
      if ( not(self.port) ) then
        if ( self.proto:match("https") ) then
          self.port = 443
        elseif ( self.proto:match("http")) then
          self.port = 80
        end
      end

      self.path  = self.file:match("^([^?]*)[%?]?")
      self.dir   = self.path:match("^(.+%/)") or "/"
      self.domain= self.host:match("^[^%.]-%.(.*)")
      return true
    elseif( self.raw:match("^javascript:") ) then
      stdnse.debug2("%s: Skipping javascript url: %s", LIBRARY_NAME, self.raw)
    elseif( self.raw:match("^mailto:") ) then
      stdnse.debug2("%s: Skipping mailto link: %s", LIBRARY_NAME, self.raw)
    else
      stdnse.debug2("%s: WARNING: Failed to parse url: %s", LIBRARY_NAME, self.raw)
    end
    return false
  end,

  -- Gets the host portion of the URL
  -- @return host string containing the hostname
  getHost = function(self) return self.host end,

  -- Gets the protocol representation of the URL
  -- @return proto string containing the protocol (ie. http, https)
  getProto = function(self) return self.proto end,

  -- Returns the filename component of the URL.
  -- @return file string containing the path and query components of the url
  getFile = function(self) return self.file end,

  -- Gets the port component of the URL
  -- @return port number containing the port of the URL
  getPort = function(self) return self.port end,

  -- Gets the path component of the URL
  -- @return the full path and filename of the URL
  getPath = function(self) return self.path end,

  -- Gets the directory component of the URL
  -- @return directory string containing the directory part of the URL
  getDir  = function(self) return self.dir end,

  -- Gets the domain component of the URL
  -- @return domain string containing the hosts domain
  getDomain = function(self)
    if ( self.domain ) then
      return self.domain
      -- fallback to the host, if we can't find a domain
    else
      return self.host
    end
  end,

  -- Converts the URL to a string
  -- @return url string containing the string representation of the url
  __tostring = function(self) return self.raw end,
}

-- An UrlQueue
UrlQueue = {

  -- creates a new instance of UrlQueue
  -- @param options table containing options
  -- @return o new instance of UrlQueue
  new = function(self, options)
    local o = {
      urls = {},
      options = options
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- gets the next available url in the queue
  getNext = function(self)
    return table.remove(self.urls,1)
  end,

  -- adds a new url to the queue
  -- @param url can be either a string or a URL or a table of URLs
  add = function(self, url)
    assert( type(url) == 'string' or type(url) == 'table', "url was neither a string or table")
    local urls = ( 'string' == type(url) ) and URL:new(url) or url

    -- if it's a table, it can be either a single URL or an array of URLs
    if ( 'table' == type(url) and url.raw ) then
      urls = { url }
    end

    for _, u in ipairs(urls) do
      u = ( 'string' == type(u) ) and URL:new(u) or u
      if ( u ) then
        table.insert(self.urls, u)
      else
        stdnse.debug1("ERROR: Invalid URL: %s", url)
      end
    end
  end,

  -- dumps the contents of the UrlQueue
  dump = function(self)
    for _, url in ipairs(self.urls) do
      print("url:", url)
    end
  end,

}

-- The Crawler class
Crawler = {

  options = {},

  removewww = function(url) return string.gsub(url, "^www%.", "") end,

  -- An utility when defining closures. Checks if the resource exists within host.
  -- @param u URL that points to the resource we want to check.
  iswithinhost = function(self, u)
    local parsed_u = url.parse(tostring(u))
    if ( self.options.base_url:getPort() ~= 80 and self.options.base_url:getPort() ~= 443 ) then
      if ( tonumber(parsed_u.port) ~= tonumber(self.options.base_url:getPort()) ) then
        return false
      end
    elseif ( parsed_u.scheme ~= self.options.base_url:getProto() ) then
      return false
      -- if urls don't match only on the "www" prefix, then they are probably the same
    elseif ( parsed_u.host == nil or self.removewww(parsed_u.host:lower()) ~= self.removewww(self.options.base_url:getHost():lower()) ) then
      return false
    end
    return true
  end,

  -- An utility when defining closures. Checks if the resource exists within domain.
  -- @param u URL that points to the resource we want to check.
  iswithindomain = function(self, u)
    local parsed_u = url.parse(tostring(u))
    if ( self.options.base_url:getPort() ~= 80 and self.options.base_url:getPort() ~= 443 ) then
      if ( tonumber(parsed_u.port) ~= tonumber(self.options.base_url:getPort()) ) then
        return false
      end
    elseif ( parsed_u.scheme ~= self.options.base_url:getProto() ) then
      return false
    elseif ( parsed_u.host == nil or parsed_u.host:sub(-#self.options.base_url:getDomain()):lower() ~= self.options.base_url:getDomain():lower() ) then
      return false
    end
    return true
  end,

  -- An utility when defining closures. Checks the type of the resource.
  -- @param u URL that points to the resource we want to check.
  -- @param ext the extension of the resource.
  -- @param signs table of signs that may exist after the extension of the resource.
  isresource = function(self, u, ext, signs)
    u = tostring(u)

    if string.match(u, "." .. ext .. "$") then
      return true
    end

    local signstring = ""
    if signs then
      for _, s in signs do
        signstring = signstring .. s
      end
      signstring:gsub('?', '%?')
    else
      signstring = "#%?"
    end

    return string.match(u, "." .. ext .. "[" .. signstring .. "]" .. "[^.]*$")

  end,

  -- creates a new instance of the Crawler instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param url string containing the relative URL
  -- @param options table of options:
  --        <code>noblacklist</code> - do not load default blacklist
  --        <code>base_url</code> - start url to crawl
  --        <code>timeout</code> - timeout for the http request
  --        <code>maxdepth</code> - the maximum directory depth to crawl
  --        <code>maxpagecount</code> - the maximum amount of pages to retrieve
  --        <code>withinhost</code> - stay within the host of the base_url
  --        <code>withindomain</code> - stay within the base_url domain
  --        <code>doscraping</code> - Permit scraping
  --        <code>scriptname</code> - should be set to SCRIPT_NAME to enable
  --                                  script specific arguments.
  --        <code>redirect_ok</code> - redirect_ok closure to pass to http.get function
  --        <code>no_cache</code> -  no_cache option to pass to http.get function
  -- @return o new instance of Crawler or nil on failure
  new = function(self, host, port, url, options)
    local o = {
      host = host,
      port = port,
      url = url,
      options = options or {},
      basethread = stdnse.base(),
    }

    setmetatable(o, self)
    self.__index = self

    self.options = o

    o:loadScriptArguments()
    o:loadLibraryArguments()
    o:loadDefaultArguments()

    local response = http.get(o.host, o.port, '/', { timeout = o.options.timeout, redirect_ok = o.options.redirect_ok, no_cache = o.options.no_cache } )

    if ( not(response) or 'table' ~= type(response) ) then
      return
    end

    o.url = o.url:match("/?(.*)")

    local u_host = o.host.targetname or o.host.name
    if ( not(u_host) or 0 == #u_host ) then
      u_host = o.host.ip
    end
    local u = ("%s://%s:%d/%s"):format(response.ssl and "https" or "http", u_host, o.port.number, o.url)
    o.options.base_url = URL:new(u)
    o.options = Options:new(o.options)
    o.urlqueue = UrlQueue:new(o.options)
    o.urlqueue:add(o.options.base_url)

    o.options.timeout = o.options.timeout or 10000
    o.processed = {}

    -- script arguments have precedence
    if ( not(o.options.maxdepth) ) then
      o.options.maxdepth = tonumber(stdnse.get_script_args("httpspider.maxdepth"))
    end

    -- script arguments have precedence
    if ( not(o.options.maxpagecount) ) then
      o.options.maxpagecount = tonumber(stdnse.get_script_args("httpspider.maxpagecount"))
    end

    if ( not(o.options.noblacklist) ) then
      o:addDefaultBlacklist()
    end

    if ( o.options.useheadfornonwebfiles ) then
      -- Load web files extensions from a file in nselib/data folder.
      -- For more information on individual file formats, see
      -- http://en.wikipedia.org/wiki/List_of_file_formats.
      o.web_files_extensions = {}
      local f = nmap.fetchfile("nselib/data/http-web-files-extensions.lst")
      if f then
        for l in io.lines(f) do
          table.insert(o.web_files_extensions, l)
        end
      end
    end

    stdnse.debug2("%s: %s", LIBRARY_NAME, o:getLimitations())

    return o
  end,

  -- Sets the timeout used by the http library
  -- @param timeout number containing the timeout in ms.
  set_timeout = function(self, timeout)
    self.options.timeout = timeout
  end,

  -- Gets the amount of pages that has been retrieved
  -- @return count number of pages retrieved by the instance
  getPageCount = function(self)
    local count = 1
    for url in pairs(self.processed) do
      count = count + 1
    end
    return count
  end,

  -- Adds a default blacklist blocking binary files such as images,
  -- compressed archives and executable files
  addDefaultBlacklist = function(self)
    local extensions = {
      image_extensions = {"png","jpg","jpeg","gif","bmp"},
      video_extensions = {"avi","flv","ogg","mp4","wmv"},
      audio_extensions = {"aac","m4a","mp3","wav"},
      doc_extensions = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
      "ppt", "pptx", "pptm", "odf", "ods", "odp", "ps", "xps"},
      archive_extensions = {"zip", "tar.gz", "gz", "rar", "7z", "sit", "sitx",
      "tgz", "tar.bz", "tar", "iso"},
      exe_extensions = {"exe", "com", "msi", "bin","dmg"}
    }
    local blacklist = {}
    for _, cat in pairs(extensions) do
      for _, ext in ipairs(cat) do
        table.insert(blacklist, string.format(".%s$", ext))
      end
    end

    self.options:addBlacklist( function(url)
        local p = url:getPath():lower()
        for _, pat in ipairs(blacklist) do
          if ( p:match(pat) ) then
            return true
          end
        end
      end )
  end,

  -- does the heavy crawling
  --
  -- The crawler may exit due to a number of different reasons, including
  -- invalid options, reaching max count or simply running out of links
  -- We return a false status for all of these and in case the error was
  -- unexpected or requires attention we set the error property accordingly.
  -- This way the script can alert the user of the details by calling
  -- getError()
  crawl_thread = function(self, response_queue)
    local condvar = nmap.condvar(response_queue)

    if ( false ~= self.options.withinhost and false ~= self.options.withindomain ) then
      table.insert(response_queue, { false, { err = true, reason = "Invalid options: withinhost and withindomain can't both be true" } })
      condvar "signal"
      return
    end

    while(true) do

      if ( self.quit or coroutine.status(self.basethread) == 'dead'  ) then
        table.insert(response_queue, {false, { err = false, msg = "Quit signalled by crawler" } })
        break
      end

      -- in case the user set a max page count to retrieve check how many
      -- pages we have retrieved so far
      local count = self:getPageCount()
      if ( self.options.maxpagecount and
          ( self.options.maxpagecount > 0 ) and
          ( count > self.options.maxpagecount ) ) then
        table.insert(response_queue, { false, { err = false, msg = "Reached max page count" } })
        condvar "signal"
        return
      end

      -- pull links from the queue until we get a valid one
      local url
      repeat
        url = self.urlqueue:getNext()
      until( not(url) or not(self.processed[tostring(url)]) )

      -- if no url could be retrieved from the queue, abort ...
      if ( not(url) ) then
        table.insert(response_queue, { false, { err = false, msg = "No more urls" } })
        condvar "signal"
        return
      end

      if ( self.options.maxpagecount ) then
        stdnse.debug2("%s: Fetching url [%d of %d]: %s", LIBRARY_NAME, count, self.options.maxpagecount, tostring(url))
      else
        stdnse.debug2("%s: Fetching url: %s", LIBRARY_NAME, tostring(url))
      end

      local scrape = true


      if not (self.options.doscraping(url)) then
        stdnse.debug2("%s: Scraping is not allowed for url: %s", LIBRARY_NAME, tostring(url))
        scrape = false
      end

      local response
      -- in case we want to use HEAD rather than GET for files with certain extensions
      if ( self.options.useheadfornonwebfiles ) then
        local is_web_file = false
        local file = url:getPath():lower()
        -- check if we are at a URL with 'no extension', for example: nmap.org/6
        if string.match(file,".*(/[^/%.]*)$") or string.match(file, "/$") then is_web_file = true end
        if not is_web_file then
          for _,v in pairs(self.web_files_extensions) do
            if string.match(file, "%."..v.."$") then
              is_web_file = true
              break
            end
          end
        end
        if is_web_file then
          stdnse.debug2("%s: Using GET: %s", LIBRARY_NAME, file)
          response = http.get(url:getHost(), url:getPort(), url:getFile(), { timeout = self.options.timeout, redirect_ok = self.options.redirect_ok, no_cache = self.options.no_cache } )
        else
          stdnse.debug2("%s: Using HEAD: %s", LIBRARY_NAME, file)
          response = http.head(url:getHost(), url:getPort(), url:getFile())
        end
      else
        -- fetch the url, and then push it to the processed table
        response = http.get(url:getHost(), url:getPort(), url:getFile(), { timeout = self.options.timeout, redirect_ok = self.options.redirect_ok, no_cache = self.options.no_cache } )
      end

      self.processed[tostring(url)] = true

      if ( response ) then
        -- were we redirected?
        if ( response.location ) then
          -- was the link absolute?
          local link = response.location[#response.location]
          if ( link:match("^http") ) then
            url = URL:new(link)
            -- guess not
          else
            url.path = link
          end
        end
        -- if we have a response, proceed scraping it
        if ( response.body ) and scrape then
          local links = LinkExtractor:new(url, response.body, self.options):getLinks()
          self.urlqueue:add(links)
        end
      else
        response = { body = "", headers = {} }
      end
      table.insert(response_queue, { true, { url = url, response = response } } )
      while ( PREFETCH_SIZE < #response_queue ) do
        stdnse.debug2("%s: Response queue full, waiting ...", LIBRARY_NAME)
        condvar "wait"
      end
      condvar "signal"
    end
    condvar "signal"
  end,

  -- Loads the argument set on a script level
  loadScriptArguments = function(self)
    local sn = self.options.scriptname
    if ( not(sn) ) then
      stdnse.debug1("%s: WARNING: Script argument could not be loaded as scriptname was not set", LIBRARY_NAME)
      return
    end

    if ( nil == self.options.maxdepth ) then
      self.options.maxdepth = tonumber(stdnse.get_script_args(sn .. ".maxdepth"))
    end
    if ( nil == self.options.maxpagecount ) then
      self.options.maxpagecount = tonumber(stdnse.get_script_args(sn .. ".maxpagecount"))
    end
    if ( nil == self.url ) then
      self.url = stdnse.get_script_args(sn .. ".url")
    end
    if ( nil == self.options.withinhost ) then
      self.options.withinhost = stdnse.get_script_args(sn .. ".withinhost")
    end
    if ( nil == self.options.withindomain ) then
      self.options.withindomain = stdnse.get_script_args(sn .. ".withindomain")
    end
    if ( nil == self.options.noblacklist ) then
      self.options.noblacklist = stdnse.get_script_args(sn .. ".noblacklist")
    end
    if ( nil == self.options.useheadfornonwebfiles ) then
      self.options.useheadfornonwebfiles = stdnse.get_script_args(sn .. ".useheadfornonwebfiles")
    end
    if ( nil == self.options.doscraping ) then
      self.options.doscraping = stdnse.get_script_args(sn .. ".doscraping")
    end

  end,

  -- Loads the argument on a library level
  loadLibraryArguments = function(self)
    local ln = LIBRARY_NAME

    if ( nil == self.options.maxdepth ) then
      self.options.maxdepth = tonumber(stdnse.get_script_args(ln .. ".maxdepth"))
    end
    if ( nil == self.options.maxpagecount ) then
      self.options.maxpagecount = tonumber(stdnse.get_script_args(ln .. ".maxpagecount"))
    end
    if ( nil == self.url ) then
      self.url = stdnse.get_script_args(ln .. ".url")
    end
    if ( nil == self.options.withinhost ) then
      self.options.withinhost = stdnse.get_script_args(ln .. ".withinhost")
    end
    if ( nil == self.options.withindomain ) then
      self.options.withindomain = stdnse.get_script_args(ln .. ".withindomain")
    end
    if ( nil == self.options.noblacklist ) then
      self.options.noblacklist = stdnse.get_script_args(ln .. ".noblacklist")
    end
    if ( nil == self.options.useheadfornonwebfiles ) then
      self.options.useheadfornonwebfiles = stdnse.get_script_args(ln .. ".useheadfornonwebfiles")
    end
    if ( nil == self.options.doscraping ) then
      self.options.doscraping = stdnse.get_script_args(ln .. ".doscraping")
    end
  end,

  -- Loads any defaults for arguments that were not set
  loadDefaultArguments = function(self)
    local function tobool(b)
      if ( nil == b ) then
        return
      end
      assert("string" == type(b) or "boolean" == type(b) or "number" == type(b), "httpspider: tobool failed, unsupported type")
      if ( "string" == type(b) ) then
        if ( "true" == b ) then
          return true
        else
          return false
        end
      elseif ( "number" == type(b) ) then
        if ( 1 == b ) then
          return true
        else
          return false
        end
      end
      return b
    end

    if self.options.withinhost == 0 then
      self.options.withinhost = false
    end

    if self.options.withindomain == 0 then
      self.options.withindomain = false
    end

    -- fixup some booleans to make sure they're actually booleans
    self.options.noblacklist = tobool(self.options.noblacklist)
    self.options.useheadfornonwebfiles = tobool(self.options.useheadfornonwebfiles)

    if ( self.options.withinhost == nil ) then
      if ( self.options.withindomain ~= true ) then
        self.options.withinhost = true
      else
        self.options.withinhost = false
      end
    end
    if ( self.options.withindomain == nil ) then
      self.options.withindomain = false
    end
    if ( not ( type(self.options.doscraping) == "function" ) ) then
      self.options.doscraping = false
    end
    self.options.maxdepth = tonumber(self.options.maxdepth) or 3
    self.options.maxpagecount = tonumber(self.options.maxpagecount) or 20
    self.url = self.url or '/'
  end,

  -- gets a string of limitations imposed on the crawl
  getLimitations = function(self)
    local o = self.options
    local limits = {}
    if ( o.maxdepth > 0 or o.maxpagecount > 0 or
        o.withinhost or o.withindomain ) then
      if ( o.maxdepth > 0 ) then
        table.insert(limits, ("maxdepth=%d"):format(o.maxdepth))
      end
      if ( o.maxpagecount > 0 ) then
        table.insert(limits, ("maxpagecount=%d"):format(o.maxpagecount))
      end
      if ( o.withindomain ) then
        table.insert(limits, ("withindomain=%s"):format(o.base_url:getDomain() or o.base_url:getHost()))
      end
      if ( o.withinhost ) then
        table.insert(limits, ("withinhost=%s"):format(o.base_url:getHost()))
      end
    end

    if ( #limits > 0 ) then
      return ("Spidering limited to: %s"):format(stdnse.strjoin("; ", limits))
    end
  end,

  -- does the crawling
  crawl = function(self)
    self.response_queue = self.response_queue or {}
    local condvar = nmap.condvar(self.response_queue)
    if ( not(self.thread) ) then
      self.thread = stdnse.new_thread(self.crawl_thread, self, self.response_queue)
    end

    if ( #self.response_queue == 0 and coroutine.status(self.thread) ~= 'dead') then
      condvar "wait"
    end
    condvar "signal"
    if ( #self.response_queue == 0 ) then
      return false, { err = false, msg = "No more urls" }
    else
      return table.unpack(table.remove(self.response_queue, 1))
    end
  end,

  -- signals the crawler to stop
  stop = function(self)
    local condvar = nmap.condvar(self.response_queue)
    self.quit = true
    condvar "signal"
    if ( coroutine.status(self.thread) == "dead" ) then
      return
    end
    condvar "wait"
  end
}

return _ENV;
