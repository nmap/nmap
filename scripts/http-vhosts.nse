description = [[
Searches for web virtual hostnames by making a large number of HEAD requests against http servers using common hostnames.

Each HEAD request provides a different
<code>Host</code> header. The hostnames come from a built-in default
list. Shows the names that return a document. Also shows the location of
redirections.

The domain can be given as the <code>http-vhosts.domain</code> argument or
deduced from the target's name. For example when scanning www.example.com,
various names of the form <name>.example.com are tried.
]]

---
-- @usage 
-- nmap --script http-vhosts -p 80,8080,443 <target>

-- @arg http-vhosts.domain The domain that hostnames will be prepended to, for
-- example <code>example.com</code> yields www.example.com, www2.example.com,
-- etc. If not provided, a guess is made based on the hostname.
-- @arg http-vhosts.path The path to try to retrieve. Default <code>/</code>.
-- @arg http-vhosts.collapse The limit to start collapsing results by status code. Default <code>20</code>

-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vhosts:
-- | example.com: 301 -> http://www.example.com/
-- | www.example.com: 200
-- | docs.example.com: 302 -> https://www.example.com/docs/
-- |_images.example.com: 200
--
-- @todo feature: move hostnames to an external file and allow the user to use another one
-- @internal: see http://seclists.org/nmap-dev/2010/q4/401 and http://seclists.org/nmap-dev/2010/q4/445
-- 
-- 
-- @todo feature: add option report and implement it
-- @internal after stripping sensitive info like ip, domain names, hostnames 
--           and redirection targets from the result, append it to a file 
--           that can then be uploaded. If enough info is gathered, the names 
--           will be weighted. It can be shared with metasploit
--
-- @todo feature: fill nsedoc
--
-- @todo feature: register results for other scripts (external help needed)
--
-- @todo feature: grow names list (external help needed)
--

author = "Carlos Pantelides"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "discovery", "intrusive" }

require "http"
require "stdnse"
require "string"
require "shortport"

-- List of domains to try. (Will become names like example.com,
-- abbot.example.com, admin.example.com, etc.) The list is derived from
-- Wikipedia lists of software with a web interface.
local HOSTNAMES = {
  "",
  "abbot",
  "admin",
  "adserver",
  "alpha",
  "api",
  "aptest",
  "arch",
  "artifactory",
  "assembla",
  "atd",
  "athena",
  "atollon",
  "attask",
  "attix",
  "attix5",
  "automatedqa",
  "backend",
  "backup",
  "bacula",
  "badboy",
  "basecamp",
  "bazaar",
  "beta",
  "bitkeeper",
  "bkp",
  "branch",
  "brightwork",
  "broadwave",
  "bromine",
  "bugtracker",
  "bugzilla",
  "build",
  "businessdriver",
  "campus",
  "catchlimited",
  "ccc",
  "centraldesktop",
  "cerebro",
  "civicrm",
  "clarizen",
  "clearcase",
  "clearquest",
  "clif",
  "clockingit",
  "codebeamer",
  "codendi",
  "codesourcery",
  "codeville",
  "collabtive",
  "compuware",
  "concordion",
  "conformiq",
  "cppunit",
  "crm",
  "cruisecontrol",
  "cubictest",
  "cucumber",
  "cunit",
  "cvs",
  "cvsnt",
  "darcs",
  "dartenium",
  "dcvs",
  "debbugs",
  "dev",
  "devel",
  "development",
  "devtest",
  "dieseltest",
  "digitaltester",
  "distract",
  "dolibarr",
  "dotproject",
  "dune",
  "durable",
  "duxqa",
  "dynamics",
  "easy",
  "egroupware",
  "eload",
  "elvior",
  "empirix",
  "endeavour",
  "enterprise",
  "epesi",
  "epesibim",
  "etester",
  "eventum",
  "fasttrack",
  "feng",
  "firefly",
  "flumotion",
  "flyspray",
  "fogbugz",
  "foro",
  "forum",
  "fossil",
  "frankenstein",
  "freecast",
  "froglogic",
  "frontend",
  "ftp",
  "functional",
  "functionaltester",
  "fwptt",
  "game",
  "games",
  "gamma",
  "gemini",
  "geniesys",
  "genietcms",
  "genius",
  "git",
  "glasscubes",
  "gnats",
  "goplan",
  "grinder",
  "guitar",
  "gurock",
  "hammerhead",
  "hammerora",
  "harvest",
  "helix",
  "help",
  "helpdesk",
  "home",
  "htmlunit",
  "httpunit",
  "huddle",
  "hudson",
  "hyperoffice",
  "icecast",
  "ikiwiki",
  "images",
  "incisif",
  "inflectra",
  "info",
  "informup",
  "intra",
  "intranet",
  "issuenet",
  "isupport",
  "it",
  "itcampus",
  "jabber",
  "jadeliquid",
  "jbehave",
  "jboss",
  "jcrawler",
  "jemmy",
  "jfunc",
  "jira",
  "jite",
  "jmeter",
  "jotbug",
  "journyx",
  "jtest",
  "jtrack",
  "junit",
  "jwebunit",
  "kayako",
  "kforge",
  "kkoop",
  "launchpad",
  "liberum",
  "libresource",
  "liquidplanner",
  "liquidtest",
  "list",
  "lista",
  "listas",
  "listman",
  "lists",
  "loadrunner",
  "magnetic",
  "mail",
  "mailman",
  "mantis",
  "mantisbt",
  "manual",
  "marathon",
  "matchware",
  "maven",
  "mbt",
  "media",
  "mercurial",
  "mercury",
  "merlin",
  "messagemagic",
  "mingle",
  "mks",
  "mksintegrity",
  "mojo",
  "monotone",
  "mvn",
  "nuevosoft",
  "objentis",
  "opengoo",
  "opengroup",
  "openload",
  "openproj",
  "openqa",
  "opensta",
  "openwebload",
  "optimaltest",
  "orcanos",
  "origsoft",
  "otmgr",
  "otrs",
  "passmark",
  "peercast",
  "perforce",
  "performancetester",
  "phpgroupware",
  "phprojekt",
  "phpunit",
  "pivotal",
  "pjsip",
  "planisware",
  "plastic",
  "postfix",
  "practitest",
  "primavera",
  "principal",
  "prod",
  "project",
  "projecthq",
  "projectpier",
  "projectplace",
  "projectspaces",
  "projektron",
  "projistics",
  "psnext",
  "pureagent",
  "pureload",
  "puretest",
  "pylot",
  "qadirector",
  "qaliber",
  "qaload",
  "qamanager",
  "qatraq",
  "qmetry",
  "qmtest",
  "qpack",
  "qtest",
  "qtronic",
  "qualify",
  "quickbase",
  "quicktest",
  "quicktestpro",
  "quotium",
  "rcs",
  "realese",
  "redmine",
  "remedy",
  "request",
  "research",
  "robot",
  "roundup",
  "rth",
  "s3",
  "sahi",
  "salome",
  "sap",
  "scarab",
  "sccs",
  "seam",
  "seapine",
  "search",
  "selenium",
  "sendmail",
  "services",
  "severa",
  "sharpforge",
  "shoutcast",
  "siebel",
  "silk",
  "silkcentral",
  "silkperformer",
  "simpletest",
  "simpletestmanagement",
  "simpleticket",
  "simulator",
  "sipp",
  "sipr",
  "smartesoft",
  "smartload",
  "smartqm",
  "smartscript",
  "smartsheet",
  "soap",
  "soapui",
  "software",
  "softwareresearch",
  "sourcesafe",
  "specflow",
  "spiceworks",
  "spiratest",
  "spring",
  "squish",
  "staff",
  "stage",
  "stagging",
  "static",
  "storytestiq",
  "streaming",
  "stub",
  "sugar",
  "sugarcrm",
  "supportworks",
  "svk",
  "svn",
  "synergy",
  "tag",
  "team",
  "teamcenter",
  "teamware",
  "teamwork",
  "teamworkpm",
  "techexcel",
  "telerik",
  "tenrox",
  "test",
  "test1",
  "test2",
  "testbench",
  "testcase",
  "testcomplete",
  "testdirector",
  "testdrive",
  "tester",
  "testing",
  "testitools",
  "testlink",
  "testlog",
  "testman",
  "testmanager",
  "testmaster",
  "testmasters",
  "testopia",
  "testoptimal",
  "testpartner",
  "testrail",
  "testrun",
  "testsuite",
  "testtrack",
  "testuff",
  "testup",
  "testworks",
  "texttest",
  "tigris",
  "tomcat",
  "tplan",
  "trac",
  "track",
  "tracker",
  "trackersuite",
  "tricentis",
  "trunk",
  "twist",
  "ubidesk",
  "unawave",
  "unreal",
  "utest",
  "vault",
  "verisium",
  "vnc",
  "vncrobot",
  "vperformer",
  "vpmi",
  "vtest",
  "watin",
  "watir",
  "web",
  "web2project",
  "web2test",
  "webaii",
  "webdriver",
  "webking",
  "webload",
  "webspoc",
  "wiki",
  "windmill",
  "winrunner",
  "wit",
  "workbook",
  "workengine",
  "worklenz",
  "workspace",
  "wowza",
  "wrike",
  "ws",
  "www",
  "www2",
  "xhtmlunit",
  "xml-simulator",
  "xplanner",
  "xqual",
  "xstudio",
  "youtrack",
  "zentrack",
  "zephyr",
  "zoho"
} 
-- uncomment and modify this for shorter scans
-- local HOSTNAMES = {
--   "",
--   "www",
--   "docs",
--   "images"
-- }

-- Defines domain to use, first from user and then from host
defineDomain = function(host)
  if stdnse.get_script_args("http-vhosts.domain") then return stdnse.get_script_args("http-vhosts.domain") end

  name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    local pos = string.find (name, ".",1,true)
    if not pos then return name end
    return string.sub (name, pos + 1)
  end
end

---
-- Makes a target name with a name and a domain
-- @param name string 
-- @param domain string
-- @return string
local makeTargetName = function(name,domain)
  if name == "" and domain == "" then return nil end
  if name == "" then return domain end
  if domain == "" then return name end
  return name .. "." .. domain
end


---
-- Collapses a result
-- key -> table
-- @param result table
-- @return string
local collapse = function(result) 
  local collapsed = {""}
  local limit = tonumber(stdnse.get_script_args("http-vhosts.collapse")) or 10
  for code, group in next, result do
    if  #group > limit then
      collapsed[#collapsed + 1] =  #group .. " names had status " ..  code
    else 
      for _,name in ipairs(group) do
        collapsed[#collapsed + 1] = name 
      end
    end
  end
  return table.concat(collapsed,"\n")
end

portrule = shortport.http

---
-- Script action
-- @param host table
-- @param port table
action = function(host, port)
  local service = "http"
  local domain = defineDomain(host)
  local path = stdnse.get_script_args("http-vhosts.path") or "/"
  local result = {}

  for _,name in ipairs(HOSTNAMES) do
    local http_response
    local targetname

    targetname = makeTargetName(name , domain)

    if targetname ~= nil then

      http_response = http.head(host, port, path, {header={Host=targetname}, bypass_cache=true})

      if not http_response.status  then
        if not response["ERROR"] then
          result["ERROR"]={}
        end
        result["ERROR"][result["ERROR"] + 1] = targetname
      else
        local status = tostring(http_response.status)
        if not result[status] then
          result[status]={}
        end
        if 300 <= http_response.status and http_response.status < 400 then
          result[status][#result[status] + 1] = targetname .. " : " .. status .. " -> " .. (http_response.header.location or "(no Location provided)")
        else 
          result[status][#result[status] + 1] = targetname .. " : " .. status
        end
      end
    end
  end
  return collapse(result)
end
