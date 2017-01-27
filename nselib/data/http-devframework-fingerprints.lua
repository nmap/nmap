local http = require "http"
local io = require "io"
local string = require "string"
local table = require "table"

---
-- http-devframework-fingerprints.lua
-- This file contains fingerprint data for http-devframework.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
--   * <code>rapidDetect</code> - Callback function that is called in the beginning
--   of detection process. It takes the host and port of the target website as
--   arguments.
--   * <code>consumingDetect</code> - Callback function that is called for each
--   spidered page. It takes the body of the response (HTML source code) and the
--   requested path as arguments.
---


tools = { Django = { rapidDetect = function(host, port)

      -- Check if the site gives that familiar Django admin login page.
      local response = http.get(host, port, "/admin/")

      if response.body then
        if string.find(response.body, "Log in | Django site admin") or
          string.find(response.body, "this_is_the_login_form") or
          string.find(response.body, "csrfmiddlewaretoken") then
          return "Django detected. Found Django admin login page on /admin/"
        end
      end

      -- In Django, the cookie sessionid is being set when you log in
      -- and forms will probably set a cookie called csrftoken.
      if response.cookies then
        for _, c in pairs(response.cookies) do
          if c.name == "csrftoken" then
            return "Django detected. Found sessionid cookie which means the contrib.auth package for authentication is enabled."
          elseif c.name == "sessionid" then
            return "Django detected. Found csrftoken cookie."
          end
        end
      end

      -- See if DEBUG mode still happens to be true.
      response = http.get(host, port, "/random404page/")

      if response.body then
        if string.find(response.body, "<code>DEBUG = True</code>") then
          return "Django detected. Found Django error page on /random404page/"
        end
      end

    end,

    consumingDetect = function(page, path)
      if page then
        if string.find(page, "csrfmiddlewaretoken") then
          return "Django detected. Found csrfmiddlewaretoken on " .. path
        end
        if string.find(page, "id=\"id_") then
          return "Django detected. Found id_ preffix in id attribute name on " .. path
        end
        if string.find(page, "%-TOTAL%-FORMS") or string.find(page, "%-DELETE") then
          return "Django detected. Found -TOTAL-FORMS and -DELETE hidden inputs, which means there is a Django formset on " .. path
        end
      end
    end
  },

  RubyOnRails = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      -- Check for Mongrel or Passenger in the "Server" or "X-Powered-By" header
      for h, v in pairs(response.header) do
        if h == "x-powered-by" or h == "server" then
          local vl = v:lower()
          local m = vl:match("mongrel") or vl:match("passenger")
          if m then
            return "RoR detected. Found '" .. m .. "' in " .. h .. " header sent by the server."
          end
        end
      end

      --  /rails/info/propertires shows project info when in development mode
      response = http.get(host, port, "/rails/info/properties")

      if response.body then
        if string.find(response.body, "Ruby version") then
          return "RoR detected. Found properties file on /rails/info/properties/"
        end
      end

      -- Make up a bad path and match the error page
      response = http.get(host, port, "/random404page/")

      if response.body then
        if string.find(response.body, "Routing Error") then
          return "RoR detected. Found RoR routing error page on /random404page/"
        end
      end

    end,

    consumingDetect = function(page, path)

      -- Check the source and look for csrf patterns.
      if page then
        if string.find(page, "csrf%-param") or string.find(page, "csrf%-token") then
          return "RoR detected. Found csrf field on" .. path
        end
      end

    end
  },


  ASPdotNET = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      -- Look for an ASP.NET header.
      for h, v in pairs(response.header) do
        local vl = v:lower()
        if h == "x-aspnet-version" or string.find(vl, "asp") then
          return "ASP.NET detected. Found related header."
        end
      end

      if response.cookies then
        for _, c in pairs(response.cookies) do
          if c.name == "aspnetsessionid" then
            return "ASP.NET detected. Found aspnetsessionid cookie."
          end
        end
      end
    end,

    consumingDetect = function(page, path)
      -- Check the source and look for common traces.
      if page then
        if string.find(page, " __VIEWSTATE") or
          string.find(page, "__EVENT") or
          string.find(page, "__doPostBack") or
          string.find(page, "aspnetForm") or
          string.find(page, "ctl00_") then
          return "ASP.NET detected. Found common traces on" .. path
        end
      end
    end
  },

  CodeIgniter = { rapidDetect = function(host, port)

      -- Match default error page.
      local response = http.get(host, port, "/random404page/")

      if response.body then
        if string.find(response.body, "#990000") and
          string.find(response.body, "404 Page Not Found") then
          return "CodeIgniter detected. Found CodeIgniter default error page on /random404page/"
        end
      end

    end,

    consumingDetect = function(page, path)
      return
    end
  },

  CakePHP = { rapidDetect = function(host, port)


      -- Find CAKEPHP header.
      local response = http.get(host, port, "/")

      for h, v in pairs(response.header) do
        local vl = v:lower()
        if string.find(vl, "cakephp") then
          return "CakePHP detected. Found related header."
        end
      end

    end,

    consumingDetect = function(page, path)
      return
    end
  },

  Symfony = { rapidDetect = function(host, port)

      -- Find Symfony header.
      local response = http.get(host, port, "/")

      for h, v in pairs(response.header) do
        local vl = v:lower()
        if string.find(vl, "symfony") then
          return "Symfony detected. Found related header."
        end
      end

    end,

    consumingDetect = function(page, path)
      return
    end
  },

  Wordpress = { rapidDetect = function(host, port)

      -- Check for common traces in the source code.
      local response = http.get(host, port, "/")

      if response.body then
        if string.find(response.body, "content=[\"']WordPress") or
          string.find(response.body, "wp%-content") then
          return "Wordpress detected. Found common traces on /"
        end
      end

      -- Check if the default login page exists.
      response = http.get(host, port, "/wp%-login")

      if response.status == "200" then
        return "Wordpress detected. Found WP login page on /wp-login"
      end
    end,

    consumingDetect = function(page, path)
      if page then
        if string.find(page, "content=[\"']WordPress") or
          string.find(page, "wp%-content") then
          return "Wordpress detected. Found common traces on " .. page
        end
      end
    end
  },

  Joomla = { rapidDetect = function(host, port)


      -- Check for common traces in the source code.
      local response = http.get(host, port, "/")

      if response.body then
        if string.find(response.body, "content=[\"']Joomla!") then
          return "Joomla detected. Found common traces on /"
        end
      end

      -- Check if the default login page exists.
      response = http.get(host, port, "/administrator")

      if response.body and string.find(response.body, "Joomla") then
        return "Joomla detected. Found Joomla login page on /administrator/"
      end

    end,

    consumingDetect = function(page, path)
      if page and string.find(page, "content=[\"']Joomla!") then
        return "Joomla detected. Found common traces on " .. page
      end
    end
  },

  Drupal = { rapidDetect = function(host, port)

      -- Check for common traces in the source code.
      local response = http.get(host, port, "/")

      if response.body then
        if string.find(response.body, "content=[\"']Drupal") then
          return "Drupal detected. Found common traces on /"
        end
      end
    end,

    consumingDetect = function(page, path)
      if page and string.find(page, "content=[\"']Drupal") then
        return "Drupal detected. Found common traces on " .. page
      end
    end
  },

  MediaWiki = { rapidDetect = function(host, port)

      -- Check for common traces in the source code.
      local response = http.get(host, port, "/")

      if response.body then
        if string.find(response.body, "content=[\"']MediaWiki") or
          string.find(response.body, "/mediawiki/") then
          return "MediaWiki detected. Found common traces on /"
        end
      end
    end,

    consumingDetect = function(page, path)
      if page and string.find(page, "content=[\"']MediaWiki") or
        string.find(page, "/mediawiki/") then
        return "MediaWiki detected. Found common traces on " .. page
      end
    end
  },

  ColdFusion = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      if response.cookies then
        for _, c in pairs(response.cookies) do
          if c.name == "cfid" or c.name == "cftoken" then
            return "ColdFusion detected. Found " .. c.name .. " cookie."
          end
        end
      end
    end,

    consumingDetect = function(page, path)
      return
    end
  },

  Broadvision = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      if response.cookies then
        for _, c in pairs(response.cookies) do
          if string.find(c.name, "bv_") then
            return "Broadvision detected. Found " .. c.name .. " cookie."
          end
        end
      end
    end,

    consumingDetect = function(page, path)
      return
    end
  },

  WebSphereCommerce = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      if response.cookies then
        for _, c in pairs(response.cookies) do
          if string.find(c.name, "wc_") then
            return "WebSphere Commerce detected. Found " .. c.name .. " cookie."
          end
        end
      end
    end,

    consumingDetect = function(page, path)
      return
    end
  },

  SPIP = { rapidDetect = function(host, port)

      local response = http.get(host, port, "/")

      if response and response.status == 200 then
          local header_composed_by = response.header['composed-by']
          -- Check in Composed-by header for the version
          if header_composed_by ~= nil then
              local version = string.match(header_composed_by, ('SPIP (%d+%.%d+%.%d+)'))
              if version ~= nil then
                return "Version of the SPIP install is " .. version
              end
          end
      end
    end,

    consumingDetect = function(page, path)
      return
    end
  },

}
