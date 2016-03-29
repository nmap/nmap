local io = require "io"
local string = require "string"
local table = require "table"

---HTTP Fingerprint files, compiled by Ron Bowes with a special thanks to...
-- o Kevin Johnson (@secureideas) for the fingerprints that come with Yokoso
--   http://yokoso.inguardians.com
-- o Jason H. (@jhaddix) for helping out with a whole pile of fingerprints he's
--   collected
-- o Bob Dooling
-- o Robert Rowley for the awesome open source cms and README checks
--   http://www.irvineunderground.org
--
-- This file is released under the Nmap license; see:
--  https://nmap.org/book/man-legal.html
--
-- @args http-fingerprints.nikto-db-path Looks at the given path for nikto database.
--       It then converts the records in nikto's database into our Lua table format
--       and adds them to our current fingerprints if they don't exist already.
--       Unfortunately, our current implementation has some limitations:
--          * It doesn't support records with more than one 'dontmatch' patterns for
--            a probe.
--          * It doesn't support logical AND for the 'match' patterns.
--          * It doesn't support sending additional headers for a probe.
--       That means, if a nikto fingerprint needs one of the above features, it
--       won't be loaded. At the time of writing this, 6546 out of the 6573 Nikto
--       fingerprints are being loaded successfully.  This runtime Nikto fingerprint integration was suggested by Nikto co-author Chris Sullo as described at http://seclists.org/nmap-dev/2013/q4/292
--
-- Although this format was originally modeled after the Nikto format, that ended
-- up being too restrictive. The current format is a simple Lua table. There are many
-- advantages to this technique; it's powerful, we don't need to write custom parsing
-- code, anybody who codes in Lua can easily add checks, and we can write converters
-- to read Nikto and other formats if we want to.
--
-- The 'fingerprints' table is the key. It's an array of checks that will be run in the
-- order they're given. Each check consists of a path, zero or more matches, output text,
-- and other optional fields. Here are all the currently defined fields:
--
-- fingerprint.probes
-- A list of one or more probes to send to the server. Each probe is either a table containing
-- the key 'path' (and potentially others), or it's a string indicating the path.
--
-- fingerprint.probes[i].path
-- The URI to check, optionally containing GET arguments. This should start with a '/'
-- and, if it's a directory, end with a '/'.
--
-- fingerprint.probes[i].method [optional; default: 'GET'}}]
-- The HTTP method to use when making requests ('GET'}}, 'POST', 'HEAD', 'PUT', 'DELETE', etc
--
-- fingerprint.ignore_404 [optional; default: false]
-- If set, the automatic checks for 404 and custom 404 pages are disabled for that check.
-- Every page will be included unless fingerprint.matches.dontmatch excludes it.
--
-- fingerprint.severity [optional; default: 1]
-- Give a severity rating, if it's a vulnerability. The scale is:
-- 1 - Info
-- 2 - Low priority
-- 3 - Warning
-- 4 - Critical
--
-- fingerprint.matches
-- An array of tables, each of which contains three fields. These will be checked, starting
-- from the first, until one is matched. If there is no 'match' text, it will fire as long
-- as the result isn't a 404. This match is not case sensitive.
--
-- fingerprint.matches[i].match
-- A string (specifically, a Lua pattern) that has to be found somewhere in the output to
-- count as a match. The string can be in the status line, in a header, or in the body.
-- In addition to matching, this field can contain captures that'll be included in the
-- output. See: http://lua-users.org/wiki/PatternsTutorial
--
-- fingerprint.matches[i].dontmatch
-- A string (specifically, a lua pattern) that cannot be found somewhere in the output.
-- This takes precedence over any text matched in the 'match' field
--
-- fingerprint.matches[i].output
-- The text to output if this match happens. If the 'match' field contains captures, these
-- captures can be used with \1, \2, etc.
--
-- If you have any questions, feel free to email dev@nmap.org or contact Ron Bowes!
--
-- CHANGELOG:
-- Added 120 new signatures taken from exploit-db.com archives from July 2009 to July 2011 [Paulino Calderon]
-- Added the option to read nikto's database and make use of its fingerprints. [George Chatzisofroniou]
--

fingerprints = {};

------------------------------------------------
----           GENERAL CHECKS               ----
------------------------------------------------
-- These are checks for generic paths, like /wiki, /images, /admin, etc

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of .*(Apache.*) Server at',
        output = 'Root directory w/ listing on \'\\1\''
      },
      {
        match = '<title>Index of',
        output = 'Root directory w/ directory listing'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/blog/',
        method = 'HEAD'
      },
      {
        path = '/weblog/',
        method = 'HEAD'
      },
      {
        path = '/weblogs/',
        method = 'HEAD'
      },
      {
        path = '/wordpress/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'Blog'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/wiki/',
        method = 'HEAD'
      },
      {
        path = '/mediawiki/',
        method = 'HEAD'
      },
      {
        path = '/wiki/Main_Page',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'Wiki'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/tikiwiki/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'Tikiwiki'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/mj_wwwusr',
        method = 'HEAD'
      },
      {
        path = '/majordomo/mj_wwwusr',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Majordomo2 Mailing List'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/j2ee/examples/servlets/',
        method = 'HEAD'
      },
      {
        path = '/j2ee/examples/jsp/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Oracle j2ee examples'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/dsc/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Trend Micro Data Loss Prevention Virtual Appliance'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/reg_1.htm',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Polycom IP phone'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/adr.htm',
        method = 'HEAD'
      },
      {
        path = '/line_login.htm?l=1',
        method = 'HEAD'
      },
      {
        path = '/tbook.csv',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Snom IP Phone'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/globalSIPsettings.html',
        method = 'HEAD'
      },
      {
        path = '/SIPsettingsLine1.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Aastra IP Phone'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/websvn/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'WEBSVN Repository'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/repos/',
        method = 'GET'
      },
      {
        path = '/repo/',
        method = 'GET'
      },
      {
        path = '/svn/',
        method = 'GET'
      },
      {
        path = '/cvs/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'realm=".-Subversion.-"',
        output = 'Subversion Repository'
      },
      {
        match = '',
        output = 'Possible code repository'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/archiva/index.action',
        method = 'GET'
      },
      {
        path = '/index.action',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '.*">Apache Archiva (.-)</a>',
        output = 'Apache Archiva version \\1'
      },
      {
        match = 'Apache Archiva (%d-%..-)\n',
        output = 'Apache Archiva version \\1'
      },
      {
        match = '<title>Apache Archiva \\',
        output = 'Apache Archiva'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/login.stm',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Belkin G Wireless Router'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/tools_admin.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'D-Link DIR-300'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/bsc_lan.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'D-Link DIR-300, DIR-320, DIR-615 revD'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/Manage.tri',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Linksys WRT54G2'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/logo_t.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = 'IP_SHARER WEB',
        output = 'Arris 2307'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '//system.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CMNC-200 IP Camera'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/main_configure.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Intellinet IP Camera'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/OvCgi/Toolbar.exe',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'HP OpenView Network Node Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/frontend/x3/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CPanel'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/awstatstotals/awstatstotals.php',
        method = 'HEAD'
      },
      {
        path = '/awstats/awstatstotals.php',
        method = 'HEAD'
      },
      {
        path = '/awstatstotals.php',
        method = 'HEAD'
      },
      {
        path = '/awstats/index.php',
        method = 'HEAD'
      },
      {
        path = '/awstatstotals/index.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'AWStats Totals'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/egroupware/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'eGroupware'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/calendar/cal_search.php',
        method = 'HEAD'
      },
      {
        path = '/cal_search.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ExtCalendar'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/a_viewusers.php',
        method = 'HEAD'
      },
      {
        path = '/aphpkb/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Andys PHP Knowledgebase'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/webedition/we/include/we_modules/',
        method = 'HEAD'
      },
      {
        path = '/webedition/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Web Edition'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/Examples/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Possible documentation files'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/LightNEasy.php?do=login',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'LightNEasy'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/channel_detail.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'DzTube'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/vcs',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Mitel Audio and Web Conferencing (AWC)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/ocsreports/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'OCS Inventory'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/vbseo.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'vBSEO'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/forum/',
        method = 'HEAD'
      },
      {
        path = '/forums/',
        method = 'HEAD'
      },
      {
        path = '/smf/',
        method = 'HEAD'
      },
      {
        path = '/phpbb/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'Forum'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/manager/',
        method = 'HEAD'
      },
      {
        path = '/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/',
        method = 'HEAD'
      },
      {
        path = '/admin/admin/',
        method = 'HEAD'
      },
      {
        path = '/administrator/',
        method = 'HEAD'
      },
      {
        path = '/moderator/',
        method = 'HEAD'
      },
      {
        path = '/webadmin/',
        method = 'HEAD'
      },
      {
        path = '/adminarea/',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/',
        method = 'HEAD'
      },
      {
        path = '/adminLogin/',
        method = 'HEAD'
      },
      {
        path = '/admin_area/',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/',
        method = 'HEAD'
      },
      {
        path = '/instadmin/',
        method = 'HEAD'
      },
      {
        path = '/memberadmin/',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin/',
        method = 'HEAD'
      },
      {
        path = '/adm/',
        method = 'HEAD'
      },
      {
        path = '/admin/account.php',
        method = 'HEAD'
      },
      {
        path = '/admin/index.php',
        method = 'HEAD'
      },
      {
        path = '/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/joomla/administrator',
        method = 'HEAD'
      },
      {
        path = '/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/index.html',
        method = 'HEAD'
      },
      {
        path = '/admin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/home.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.html',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.php',
        method = 'HEAD'
      },
      {
        path = '/admincp/',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.html',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/account.html',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.html',
        method = 'HEAD'
      },
      {
        path = '/admin_login.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.php',
        method = 'HEAD'
      },
      {
        path = '/cp.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.php',
        method = 'HEAD'
      },
      {
        path = '/nsw/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.php',
        method = 'HEAD'
      },
      {
        path = '/admin_login.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.php',
        method = 'HEAD'
      },
      {
        path = '/administrator.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.html',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.html',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.html',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin/home.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.php',
        method = 'HEAD'
      },
      {
        path = '/moderator.php',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.php',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.php',
        method = 'HEAD'
      },
      {
        path = '/account.php',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.php',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.php',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.html',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.html',
        method = 'HEAD'
      },
      {
        path = '/home.html',
        method = 'HEAD'
      },
      {
        path = '/rcjakar/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.html',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.html',
        method = 'HEAD'
      },
      {
        path = '/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.html',
        method = 'HEAD'
      },
      {
        path = '/cp.html',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.php',
        method = 'HEAD'
      },
      {
        path = '/moderator.html',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.html',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.html',
        method = 'HEAD'
      },
      {
        path = '/user.html',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.html',
        method = 'HEAD'
      },
      {
        path = '/administrator.html',
        method = 'HEAD'
      },
      {
        path = '/login.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.html',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.html',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.html',
        method = 'HEAD'
      },
      {
        path = '/adm/index.html',
        method = 'HEAD'
      },
      {
        path = '/adm.html',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.html',
        method = 'HEAD'
      },
      {
        path = '/user.php',
        method = 'HEAD'
      },
      {
        path = '/account.html',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.html',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.php',
        method = 'HEAD'
      },
      {
        path = '/wp-login.php',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.php',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.php',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.php',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.php',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.php',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.php',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.php',
        method = 'HEAD'
      },
      {
        path = '/admin2.php',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.php',
        method = 'HEAD'
      },
      {
        path = '/adm/index.php',
        method = 'HEAD'
      },
      {
        path = '/adm.php',
        method = 'HEAD'
      },
      {
        path = '/affiliate.php',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.php',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.php',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.php',
        method = 'HEAD'
      },
      {
        path = '/account.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/account.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_login.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.cfm',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator.cfm',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.cfm',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/user.cfm',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/cp.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/home.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm1n/',
        method = 'HEAD'
      },
      {
        path = '/4dm1n/',
        method = 'HEAD'
      },
      {
        path = '/account.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/account.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/home.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.asp',
        method = 'HEAD'
      },
      {
        path = '/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.asp',
        method = 'HEAD'
      },
      {
        path = '/cp.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator.asp',
        method = 'HEAD'
      },
      {
        path = '/login.asp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.asp',
        method = 'HEAD'
      },
      {
        path = '/user.asp',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.asp',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_login.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.asp',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/home.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.asp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.asp',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.asp',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adm/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adm.asp',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.asp',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.asp',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.asp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/account.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/account.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/home.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.aspx',
        method = 'HEAD'
      },
      {
        path = '/cp.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator.aspx',
        method = 'HEAD'
      },
      {
        path = '/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/user.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_login.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/home.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.aspx',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.aspx',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.aspx',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/account.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/home.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.jsp',
        method = 'HEAD'
      },
      {
        path = '/cp.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator.jsp',
        method = 'HEAD'
      },
      {
        path = '/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/user.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/account.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_login.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/home.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.jsp',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.jsp',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.jsp',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin1.php',
        method = 'HEAD'
      },
      {
        path = '/administr8.asp',
        method = 'HEAD'
      },
      {
        path = '/administr8.php',
        method = 'HEAD'
      },
      {
        path = '/administr8.jsp',
        method = 'HEAD'
      },
      {
        path = '/administr8.aspx',
        method = 'HEAD'
      },
      {
        path = '/administr8.cfm',
        method = 'HEAD'
      },
      {
        path = '/administr8/',
        method = 'HEAD'
      },
      {
        path = '/administer/',
        method = 'HEAD'
      },
      {
        path = '/administracao.php',
        method = 'HEAD'
      },
      {
        path = '/administracao.asp',
        method = 'HEAD'
      },
      {
        path = '/administracao.aspx',
        method = 'HEAD'
      },
      {
        path = '/administracao.cfm',
        method = 'HEAD'
      },
      {
        path = '/administracao.jsp',
        method = 'HEAD'
      },
      {
        path = '/administracion.php',
        method = 'HEAD'
      },
      {
        path = '/administracion.asp',
        method = 'HEAD'
      },
      {
        path = '/administracion.aspx',
        method = 'HEAD'
      },
      {
        path = '/administracion.jsp',
        method = 'HEAD'
      },
      {
        path = '/administracion.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrators/',
        method = 'HEAD'
      },
      {
        path = '/adminpro/',
        method = 'HEAD'
      },
      {
        path = '/admins/',
        method = 'HEAD'
      },
      {
        path = '/admins.cfm',
        method = 'HEAD'
      },
      {
        path = '/admins.php',
        method = 'HEAD'
      },
      {
        path = '/admins.jsp',
        method = 'HEAD'
      },
      {
        path = '/admins.asp',
        method = 'HEAD'
      },
      {
        path = '/admins.aspx',
        method = 'HEAD'
      },
      {
        path = '/maintenance/',
        method = 'HEAD'
      },
      {
        path = '/Lotus_Domino_Admin/',
        method = 'HEAD'
      },
      {
        path = '/hpwebjetadmin/',
        method = 'HEAD'
      },
      {
        path = '/_admin/',
        method = 'HEAD'
      },
      {
        path = '/_administrator/',
        method = 'HEAD'
      },
      {
        path = '/_administrador/',
        method = 'HEAD'
      },
      {
        path = '/_admins/',
        method = 'HEAD'
      },
      {
        path = '/_administrators/',
        method = 'HEAD'
      },
      {
        path = '/_administradores/',
        method = 'HEAD'
      },
      {
        path = '/_administracion/',
        method = 'HEAD'
      },
      {
        path = '/_4dm1n/',
        method = 'HEAD'
      },
      {
        path = '/_adm1n/',
        method = 'HEAD'
      },
      {
        path = '/_Admin/',
        method = 'HEAD'
      },
      {
        path = '/system_administration/',
        method = 'HEAD'
      },
      {
        path = '/system-administration/',
        method = 'HEAD'
      },
      {
        path = '/system-admin/',
        method = 'HEAD'
      },
      {
        path = '/system-admins/',
        method = 'HEAD'
      },
      {
        path = '/system-administrators/',
        method = 'HEAD'
      },
      {
        path = '/administracion-sistema/',
        method = 'HEAD'
      },
      {
        path = '/Administracion/',
        method = 'HEAD'
      },
      {
        path = '/Admin/',
        method = 'HEAD'
      },
      {
        path = '/Administrator/',
        method = 'HEAD'
      },
      {
        path = '/Manager/',
        method = 'HEAD'
      },
      {
        path = '/Adm/',
        method = 'HEAD'
      },
      {
        path = '/systemadmin/',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin108/',
        method = 'HEAD'
      },
      {
        path = '/pec_admin/',
        method = 'HEAD'
      },
      {
        path = '/system/admin/',
        method = 'HEAD'
      },
      {
        path = '/plog-admin/',
        method = 'HEAD'
      },
      {
        path = '/ESAdmin/',
        method = 'HEAD'
      },
      {
        path = '/axis2-admin/',
        method = 'HEAD'
      },
      {
        path = '/_sys/',
        method = 'HEAD'
      },
      {
        path = '/admin_cp.asp',
        method = 'HEAD'
      },
      {
        path = '/sitecore/admin/',
        method = 'HEAD'
      },
      {
        path = '/sitecore/login/admin/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '<title>Index of',
        output = 'Possible admin folder w/ directory listing'
      },
      {
        output = 'Possible admin folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/backup/',
        method = 'GET'
      },
      {
        path = '/backup',
        method = 'GET'
      },
      {
        path = '/backup.sql',
        method = 'GET'
      },
      {
        path = '/backup.sql.gz',
        method = 'GET'
      },
      {
        path = '/backup.sql.bz2',
        method = 'GET'
      },
      {
        path = '/backup.zip',
        method = 'GET'
      },
      {
        path = '/backups/',
        method = 'GET'
      },
      {
        path = '/bak/',
        method = 'GET'
      },
      {
        path = '/back/',
        method = 'GET'
      },
      {
        path = '/cache/backup/',
        method = 'GET'
      },
      {
        path = '/admin/backup/',
        method = 'GET'
      },
      {
        path = '/dbbackup.txt',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of',
        output = 'Backup folder w/ directory listing'
      },
      {
        match = '',
        output = 'Possible backup'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/b.sql',
        method = 'HEAD'
      },
      {
        path = '/db.sql',
        method = 'HEAD'
      },
      {
        path = '/ddb.sql',
        method = 'HEAD'
      },
      {
        path = '/users.sql',
        method = 'HEAD'
      },
      {
        path = '/database.sql',
        method = 'HEAD'
      },
      {
        path = '/mysql.sql',
        method = 'HEAD'
      },
      {
        path = '/dump.sql',
        method = 'HEAD'
      },
      {
        path = '/respaldo.sql',
        method = 'HEAD'
      },
      {
        path = '/data.sql',
        method = 'HEAD'
      },
      {
        path = '/old.sql',
        method = 'HEAD'
      },
      {
        path = '/usuarios.sql',
        method = 'HEAD'
      },
      {
        path = '/bdb.sql',
        method = 'HEAD'
      },
      {
        path = '/1.sql',
        method = 'HEAD'
      },
      {
        path = '/admin/download/backup.sql',
        method = 'HEAD'
      }

    },
    matches = {
      {
        match = '',
        output = 'Possible database backup'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/clientaccesspolicy.xml',
        method = 'HEAD'
      },
    },
    matches = {
      {
        output = 'Microsoft Silverlight crossdomain policy'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/atom/',
        method = 'HEAD'
      },
      {
        path = '/atom.aspx',
        method = 'HEAD'
      },
      {
        path = '/atom.php',
        method = 'HEAD'
      },
      {
        path = '/atom.xml',
        method = 'HEAD'
      },
      {
        path = '/atom.jsp',
        method = 'HEAD'
      },
      {
        path = '/rss/',
        method = 'HEAD'
      },
      {
        path = '/rss.aspx',
        method = 'HEAD'
      },
      {
        path = '/rss.php',
        method = 'HEAD'
      },
      {
        path = '/rss.xml',
        method = 'HEAD'
      },
      {
        path = '/rss.jsp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'RSS or Atom feed'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/etc/passwd',
        method = 'GET'
      },
      {
        path = '/boot.ini',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'root:',
        output = 'Webroot appears to be in / (Linux)'
      },
      {
        match = 'boot loader',
        output = 'Webroot appears to be in c:\\ (Windows)'
      },
      {
        match = '',
        output = 'Webroot might be in root folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/example/',
        method = 'GET'
      },
      {
        path = '/examples/',
        method = 'GET'
      },
      {
        path = '/iissamples/',
        method = 'GET'
      },
      {
        path = '/j2eeexamples/',
        method = 'GET'
      },
      {
        path = '/j2eeexamplesjsp/',
        method = 'GET'
      },
      {
        path = '/sample/',
        method = 'GET'
      },
      {
        path = '/ncsample/',
        method = 'GET'
      },
      {
        path = '/fpsample/',
        method = 'GET'
      },
      {
        path = '/cmsample/',
        method = 'GET'
      },
      {
        path = '/samples/',
        method = 'GET'
      },
      {
        path = '/mono/1.1/index.aspx',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of .*(Apache.*) Server at',
        output = 'Sample scripts w/ listing on \'\\1\''
      },
      {
        match = '<title>Index of',
        output = 'Sample scripts w/ directory listing'
      },
      {
        match = '',
        output = 'Sample scripts'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/login/',
        method = 'HEAD'
      },
      {
        path = '/login.htm',
        method = 'HEAD'
      },
      {
        path = '/login.jsp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Login page'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/test.asp',
        method = 'HEAD'
      },
      {
        path = '/test.class',
        method = 'HEAD'
      },
      {
        path = '/test/',
        method = 'HEAD'
      },
      {
        path = '/test.htm',
        method = 'HEAD'
      },
      {
        path = '/test.html',
        method = 'HEAD'
      },
      {
        path = '/test.php',
        method = 'HEAD'
      },
      {
        path = '/test.txt',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Test page'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/webmail/',
        method = 'HEAD'
      },
      {
        path = '/mail/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Mail folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/log/',
        method = 'HEAD'
      },
      {
        path = '/log.htm',
        method = 'HEAD'
      },
      {
        path = '/log.php',
        method = 'HEAD'
      },
      {
        path = '/log.asp',
        method = 'HEAD'
      },
      {
        path = '/log.aspx',
        method = 'HEAD'
      },
      {
        path = '/log.jsp',
        method = 'HEAD'
      },
      {
        path = '/logs/',
        method = 'HEAD'
      },
      {
        path = '/logs.htm',
        method = 'HEAD'
      },
      {
        path = '/logs.php',
        method = 'HEAD'
      },
      {
        path = '/logs.asp',
        method = 'HEAD'
      },
      {
        path = '/logs.aspx',
        method = 'HEAD'
      },
      {
        path = '/logs.jsp',
        method = 'HEAD'
      },
      {
        path = '/wwwlog/',
        method = 'HEAD'
      },
      {
        path = '/wwwlogs/',
        method = 'HEAD'
      },
      {
        path = '/mail_log_files/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Logs'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/images/rails.png',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Ruby on Rails'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/mono/',
        method = 'HEAD'
      },
    },

    matches = {
      {
        match = '',
        output = 'Mono'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/robots.txt',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Robots file'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/crossdomain.xml',
        method = 'HEAD'
      },
    },
    matches = {
      {
        output = 'Adobe Flash crossdomain policy'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/css/cake.generic.css',
        method = 'HEAD'
      },
      {
        path = '/img/cake.icon.gif',
        method = 'HEAD'
      },
      {
        path = '/img/cake.icon.png',
        method = 'HEAD'
      },
      {
        path = '/js/vendors.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CakePHP application'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/ffileman.cgi?',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Ffileman Web File Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/fshow.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Horizon Web App'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/admin/upload.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Admin File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/upload_multiple_js.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'NAS Uploader'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/uploadtester.asp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Free ASP Upload Shell'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/info.php',
        method = 'HEAD'
      },
      {
        path = '/phpinfo.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Possible information file'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/kusabax/manage_page.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Kusabax Image Board'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/plus/lurking.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'phpMyChat Plus'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/adm/barra/assetmanager/assetmanager.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '360 Web Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/eyeos/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Possible eyeOS installation'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/NETWARE.HTM',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Planet FPS-1101'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/setup.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Linksys Cisco Wag120n or similar'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/debug.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Linksys WRT54G'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/ehcp/?op=applyforftpaccount',
        method = 'HEAD'
      },
      {
        path = '/ehcp/?op=applyforaccount',
        method = 'HEAD'
      },
      {
        path = '/ehcp/?op=applyfordomainaccount',
        method = 'HEAD'
      },
      {
        path = '/vhosts/ehcp/?op=applyforftpaccount',
        method = 'HEAD'
      },
      {
        path = '/vhosts/ehcp/?op=applyforaccount',
        method = 'HEAD'
      },
      {
        path = '/vhosts/ehcp/?op=applyfordomainaccount',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Easy Hosting Control Panel'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/tools_admin.cgi?',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'D-Link WBR-1310'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/level/15',
        method = 'HEAD'
      },
      {
        path = '/exec/show/log/CR',
        method = 'HEAD'
      },
      {
        path = '/level/15/exec/-/configure/http',
        method = 'HEAD'
      },
      {
        path = '/level/15/exec/-',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = 'cisco-IOS',
        output = 'Cisco 2811'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/appServer/jvmReport.jsf?instanceName=server&pageTitle=JVM%20Report',
        method = 'HEAD'
      },
      {
        path = '/common/appServer/jvmReport.jsf?pageTitle=JVM%20Report',
        method = 'HEAD'
      },
      {
        path = '/common/appServer/jvmReport.jsf?reportType=summary&instanceName=server',
        method = 'HEAD'
      }
   },
    matches = {
      {
        match = '',
        output = 'Oracle GlashFish Server Information'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/console/login/loginForm.jsp',
        method = 'HEAD'
      }
   },
    matches = {
      {
        match = '',
        output = 'Oracle WebLogic Server Administration Console'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/login_img.jpg',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = 'RapidLogic',
        output = 'AIRAYA WirelessGRID'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cirronetlogo.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = 'Cirronet Wavebolt-AP',
        output = 'Cirronet Wavebolt'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/browserId/wizardForm.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/forms/callback.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/forms/callbackICM.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/agent/AgentFrame.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/agent/default/badlogin.jhtml',
        method = 'HEAD'
      },
      {
        path = '/callme/callForm.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/multichatui/nowDefunctWindow.jhtml',
        method = 'HEAD'
      },
      {
        path = '/browserId/wizard.jhtml',
        method = 'HEAD'
      },
      {
        path = '/admin/CiscoAdmin.jhtml',
        method = 'HEAD'
      },
      {
        path = '/msccallme/mscCallForm.jhtml',
        method = 'HEAD'
      },
      {
        path = '/webline/html/admin/wcs/LoginPage.jhtml',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Cisco Collaboration Server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/restoreinfo.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Sagem router'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/confirminvite.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'phpMyBitTorrent'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/sourcebans/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'SourceBans - Steam server application'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/swfupload/index.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'SWFUpload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/mymarket/shopping/index.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'MyMarket'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/myshop_start.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'FozzCom shopping'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/piranha/secure/passwd.php3',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'RedHat Piranha Virtual Server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/ck/mimencode',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ContentKeeper Web Appliance'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/masterCGI?',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Alcatel-Lucent OmniPCX Enterprise'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/tiny_mce/plugins/filemanager/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Tiny MCE File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/upload/scp/ajax.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'osTicket / AJAX File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-mod/view_help.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Barracuda Networks Spam & Virus Firewall'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-mod/index.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Barracuda Web Application Firewall'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-mod/smtp_test.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Barracuda IM Firewall'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/TopToolArea.html',
        method = 'HEAD'
      },
      {
        path = '/switchSystem.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Alteon OS BBI (Nortell)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/intruvert/jsp/module/Login.jsp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'McAfee Network Security Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/ajaxfilemanager/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'AJAX File Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/upload/data/settings.cdb',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CF Image Hosting DB'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/fm.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Simple File Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/nagios3/cgi-bin/statuswml.cgi',
        method = 'HEAD'
      },
      {
        path = '/nagios3/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Nagios3'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/test/logon.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Jetty'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cal_cat.php',
        method = 'HEAD'
      },
      {
        path = '/calendar/cal_cat.php',
        method = 'HEAD'
      },
      {
        path = '/cal/cal_cat.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Calendarix'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/private/sdc.tgz',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'IBM Bladecenter Management Logs'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cacti/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Cacti Web Monitoring'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/cgi-bin/awstats.pl',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'AWStats'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/wiki/rankings.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Bit Weaver'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/reqdetails.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'BtiTracker'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/shared/help.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'OpenBiblio/WebBiblio Subject Gateway System'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/seti.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'PHP SETI@home'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/imc/',
        method = 'HEAD'
      },
      {
        path = '/imcws/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '3Com Intelligent Management Center'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/partymgr/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Apache OFBiz'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/Base/upload.php',
        method = 'HEAD'
      },
      {
        path = '/Base/example_1.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'MassMirror Uploader'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/YUI-upload/html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'YUI Images / File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/tools/filemanager/skins/mobile/admin1.template.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ispCP Omega'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/Uploadify/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Uploadify'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/syssite/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ShopEx'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/updown.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'PHP Uploader Downloader'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/modules/docmanager/doctypetemplates/myuploadedfile',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Achievo'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/ReqWebHelp/advanced/workingSet.jsp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'IBM Rational RequisitePro/ReqWebHelp'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/dhost/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Novell eDirectory'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/engine/api/api.class.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'DatalifeEngine'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/jsft_resource.jsf',
        method = 'HEAD'
      },
      {
        path = '/scales_static_resource.jsf',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'JSFTemplating/Mojarra Scales/GlassFish Application Server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/setup/password_required.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '2WIRE GATEWAY'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/zp-core/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Zen Photo'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/amember/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'aMember'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/.hgignore',
        method = 'HEAD'
      },
      {
        path = '/.gitignore',
        method = 'HEAD'
      },
      {
        path = '/.bzrignore',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Revision control ignore file'
      }
    }
  });

------------------------------------------------
----         SECURITY SOFTWARE              ----
------------------------------------------------
-- These checks will find specific installed software. If possible, it will also
-- find versions, etc.

table.insert(fingerprints, {
    category = 'security',
    probes = {
    {
        path = '/CSS/Miniweb.css',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'ad_header_form_sprachauswahl',
        output = 'SCADA Siemens SIMATIC S7'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/S7Web.css',
        method = 'GET'
      },
      {
        path = '/Portal0000.htm',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<td class="Title_Area_Name">(.-)</td>',
        output = 'SCADA Siemens PCS7: \\1'
      },
      {
        match = '',
        output = 'SCADA Siemens PCS7'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/arcsight/',
        method = 'HEAD'
      },
      {
        path = '/arcsight/images/logo-login-arcsight.gif',
        method = 'HEAD'
      },
      {
        path = '/arcsight/images/navbar-icon-logout-on.gif',
        method = 'HEAD'
      },
      {
        path = '/images/logo-arcsight.gif',
        method = 'HEAD'
      },
      {
        path = '/logger/monitor.ftl',
        method = 'HEAD'
      },
    },
    matches = {
      {
        output = 'Arcsight'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/beef/',
        method = 'HEAD'
      },
      {
        path = '/BEEF/',
        method = 'HEAD'
      },
      {
        path = '/beef/images/beef.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'BeEF Browser Exploitation Framework'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/gfx/form_top_left_corner.gif',
        method = 'HEAD'
      },
      {
        path = '/gfx/logout_24.png',
        method = 'HEAD'
      },
      {
        path = '/gfx/new_logo.gif',
        method = 'HEAD'
      },
      {
        path = '/javascript/sorttable.js',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Secunia NSI'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/images/btn_help_nml.gif',
        method = 'HEAD'
      },
      {
        path = '/images/hdr_icon_homeG.gif',
        method = 'HEAD'
      },
      {
        path = '/spControl.php',
        method = 'HEAD'
      },
      {
        path = '/images/isslogo.gif',
        method = 'HEAD'
      },
      {
        path = '/deploymentmanager/',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'IBM Proventia'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/i18n/EN/css/foundstone.css',
        method = 'HEAD'
      },
      {
        path = '/i18n/EN/images/external_nav_square.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Foundstone'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/officescan/console/html/cgi/cgiChkMasterPwd.exe',
        method = 'HEAD'
      },
      {
        path = '/officescan/console/html/ClientInstall/officescannt.htm',
        method = 'HEAD'
      },
      {
        path = '/officescan/console/html/images/icon_refresh.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Trend Micro OfficeScan Server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/picts/BC_bwlogorev.gif',
        method = 'HEAD'
      },
      {
        path = '/picts/menu_leaf.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'BlueCoat Reporter'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/theme/images/en/login1.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Fortinet VPN/Firewall'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/',
        method = 'GET'
      },
    },
    matches = {
      {
        match = 'id="NessusClient"',
        output = 'Nessus'
      },
      {
        match = 'NessusClient.swf',
        output = 'Nessus'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/NessusClient.swf',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Nessus'
      }
    }
  });

table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/dotDefender/',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'dotDefender Web Application Firewall'
      }
    }
  });

-- http://www.rapid7.com/db/modules/payload/windows/meterpreter/reverse_hop_http
-- "GET /hop.php?/control" will grab all pending messages, but is unreliable if
-- there are no pending messages.
table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/hop.php?/12345',
        method = 'GET'
      },
    },
    matches = {
      {
        -- TODO: this only works for Meterpreter payloads. Find a more generic means?
        match = 'METERPRETER_TRANSPORT_HTTP',
        output = 'Metasploit reverse_hop_http hop point'
      },
    }
  });

-- http://carnal0wnage.attackresearch.com/2015/02/cisco-asa-version-grabber-cve-2014-3398.html
table.insert(fingerprints, {
    category = 'security',
    probes = {
      {
        path = '/CSCOSSLC/config-auth',
        method = 'GET'
      },
    },
    matches = {
      {
        match = '<version who="sg">([^<]+)</version>',
        output = 'Cisco ASA, firmware \\1'
      },
    }
  });

------------------------------------------------
----        MANAGEMENT SOFTWARE             ----
------------------------------------------------
table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/vmware/',
        method = 'HEAD'
      },
      {
        path = '/vmware/imx/vmware_boxes-16x16.png',
        method = 'HEAD'
      },
      {
        path = '/ui/',
        method = 'HEAD'
      },
      {
        path = '/ui/imx/vmwareLogo-16x16.png',
        method = 'HEAD'
      },
      {
        path = '/ui/imx/vmwarePaperBagLogo-16x16.png',
        method = 'HEAD'
      },
      {
        path = '/ui/vManage.do',
        method = 'HEAD'
      },
      {
        path = '/client/VMware-viclient.exe',
        method = 'HEAD'
      },
      {
        path = '/en/welcomeRes.js',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'VMWare'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/citrix/',
        method = 'HEAD'
      },
      {
        path = '/Citrix/',
        method = 'HEAD'
      },
      {
        path = '/Citrix/MetaFrame/auth/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/images/ctxHeader01.jpg',
        method = 'HEAD'
      },
      {
        path = '/images/Safeword_Token.jpg',
        method = 'HEAD'
      },
      {
        path = '/sw/auth/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/vpn/images/AccessGateway.ico',
        method = 'HEAD'
      },
      {
        path = '/citrix/AccessPlatform/auth/clientscripts/',
        method = 'HEAD'
      },
      {
        path = '/AccessPlatform/auth/clientscripts/',
        method = 'HEAD'
      },
      {
        path = '/Citrix//AccessPlatform/auth/clientscripts/cookies.js',
        method = 'HEAD'
      },
      {
        path = '/Citrix/AccessPlatform/auth/clientscripts/login.js',
        method = 'HEAD'
      },
      {
        path = '/Citrix/PNAgent/config.xml',
        method = 'HEAD'
      },
    },
    matches = {
      {
        output = 'Citrix'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/cgi-bin/image/shikaku2.png',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'TeraStation PRO RAID 0/1/5 Network Attached Storage'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/config/public/usergrp.gif',
        method = 'HEAD'
      },
      {
        path = '/pictures/buttons/file_view_mark.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'AXIS StorPoint'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/cpqlogin.htm?RedirectUrl=/&RedirectQueryString=',
        method = 'HEAD'
      },
      {
        path = '/hplogo.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'HP System Management Homepage'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/ie_index.htm',
        method = 'HEAD'
      },
      {
        path = '/ilo.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'HP Integrated Lights Out'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/images/icon_server_connected.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'HP Blade Enclosure'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/mxhtml/images/signin_logo.gif',
        method = 'HEAD'
      },
      {
        path = '/mxhtml/images/status_critical_15.gif',
        method = 'HEAD'
      },
      {
        path = '/mxportal/home/en_US/servicetools.gif',
        method = 'HEAD'
      },
      {
        path = '/mxportal/home/MxPortalFrames.jsp',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'HP Insight Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/xymon/menu/menu.css',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Xymon'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/rrc.htm',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Raritan Remote Client'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/manager/html/upload',
        method = 'HEAD'
      },
      {
        path = '/manager/html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Apache Tomcat'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/axis2/axis2-web/HappyAxis.jsp',
        method = 'HEAD'
      },
      {
        path = '/axis2/',
        method = 'HEAD'
      },
      {
        path = '/happyaxis.jsp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Apache Axis2'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/web-console/ServerInfo.jsp',
        method = 'HEAD'
      },
      {
        path = '/web-console/Invoker',
        method = 'HEAD'
      },
      {
        path = '/invoker/',
        method = 'HEAD'
      },
      {
        path = '/jmx-console/',
        method = 'HEAD'
      },
      {
        path = '/admin-console/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'JBoss Console'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/CFIDE/administrator/enter.cfm',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/administrator/entman/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/cfide/install.cfm',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/administrator/archives/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/wizards/common/_logintowizard.cfm',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/componentutils/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/Administrator/startstop.html',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'ColdFusion Admin Console'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/common/help/en/go/login_ts.html',
        method = 'HEAD'
      },
      {
        path = '/system/login/',
        method = 'HEAD'
      },
      {
        path = '/system/login/reset?next=%2Fsystem%2Flogin&set-lang=en',
        method = 'HEAD'
      },
      {
        path = '/common/images/logos/img_logoMain.jpg',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = 'URL=http://www.macromedia.com/go/breeze_login_help_en',
        output = 'Adobe Acrobat Connect Pro'
      },
      {
        match = '<title>Connect Pro Central Login</title>',
        output = 'Adobe Acrobat Connect Pro'
      },
      {
        match = '<title>Forgot your password?</title>',
        output = 'Adobe Acrobat Connect Pro'
      },
      {
        match = 'Server: JRun Web Server',
        output = 'Adobe Acrobat Connect Pro'
      },
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/Dashboard/Dashboard.html',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'Server: Kodak-RulesBasedAutomation',
        output = 'Prinergy Dashboard Client Login'
      },
      {
        match = '<title>Dashboard</title>',
        output = 'Prinergy Dashboard Client Login'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/flexfm/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Flex File Manager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/lib/usermanagement/userInfo.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Testlink TestManagement'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/security/xamppsecurity.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'XAMPP'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/lc/system/console',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = 'OSGi Management Console',
        output = 'Adobe LiveCycle Management Console'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      {
        path = '/dm-albums/dm-albums.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'DM FileManager'
      }
    }
  });

table.insert(fingerprints, {
    category = 'management',
    probes = {
      "/ibm/console/logon.jsp?action=OK",
      "/console/",
      "/console/portal/0/Welcome"
    },
    matches = {
      {
        match = "[Ww][Ee][Bb][Ss][Pp][Hh][Ee][Rr][Ee]",
        output = "WebSphere"
      },
      {
        match = "WSC Console Federation",
        output = "WebSphere Commerce"
      },
    }
  })

------------------------------------------------
----     PRINTERS, WEBCAMS, PROJECTORS      ----
------------------------------------------------
table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/x_logo.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Xerox printer'
      }
    }
  });

table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/gif/hp.gif',
        method = 'HEAD'
      },
      {
        path = '/gif/hp_invent_logo.gif',
        method = 'HEAD'
      },
      {
        path = '/gif/printer.gif',
        method = 'HEAD'
      },
      {
        path = '/hp/device/this.LCDispatcher',
        method = 'HEAD'
      },
      {
        path = '/hp/device/webAccess/index.htm',
        method = 'HEAD'
      },
      {
        path = '/PageSelector.class',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'HP Printer'
      }
    }
  });

table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/images/lexbold.gif',
        method = 'HEAD'
      },
      {
        path = '/images/lexlogo.gif',
        method = 'HEAD'
      },
      {
        path = '/images/printer.gif',
        method = 'HEAD'
      },
      {
        path = '/printer/image',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Lexmark Printer'
      }
    }
  });

table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/images/mute_alloff.gif',
        method = 'HEAD'
      },
      {
        path = '/images/pic_bri.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'NEC Projector'
      }
    }
  });

table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/scanweb/images/scanwebtm.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'SCAN Web (Webcam)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'printer',
    probes = {
      {
        path = '/view/index.shtml',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Axis 212 PTZ Network Camera'
      }
    }
  });

------------------------------------------------
----              DATABASES                 ----
------------------------------------------------

--phpmyadmin db taken from http://milw0rm.com/exploits/8921
table.insert(fingerprints, {
    category = 'database',
    probes = {
      {
        path = '/phpmyadmin/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin/',
        method = 'HEAD'
      },
      {
        path = '/PHPMyAdmin/',
        method = 'HEAD'
      },
      {
        path = '/PMA/',
        method = 'HEAD'
      },
      {
        path = '/pma/',
        method = 'HEAD'
      },
      {
        path = '/dbadmin/',
        method = 'HEAD'
      },
      {
        path = '/myadmin/',
        method = 'HEAD'
      },
      {
        path = '/php-my-admin/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.2.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.2.6/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.7/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.7-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-alpha/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-alpha2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-beta2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.1-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.2/',
        method = 'HEAD'
      },
      {
        path = '/sqlmanager/',
        method = 'HEAD'
      },
      {
        path = '/php-myadmin/',
        method = 'HEAD'
      },
      {
        path = '/phpmy-admin/',
        method = 'HEAD'
      },
      {
        path = '/mysqladmin/',
        method = 'HEAD'
      },
      {
        path = '/mysql-admin/',
        method = 'HEAD'
      },
      {
        path = '/websql/',
        method = 'HEAD'
      },
      {
        path = '/_phpmyadmin/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = 'phpMyAdmin'
      }
    }
  });

table.insert(fingerprints, {
    category = 'database',
    probes = {
      {
        path = '/footer1.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = '(possible) Oracle Web server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'database',
    probes = {
      {
        path = '/homepage.nsf/homePage.gif?OpenImageResource',
        method = 'HEAD'
      },
      {
        path = '/icons/ecblank.gif',
        method = 'HEAD'
      },
      {
        path = '/852566C90012664F',
        method = 'HEAD'
      },
      {
        path = '/admin4.nsf',
        method = 'HEAD'
      },
      {
        path = '/admin5.nsf',
        method = 'HEAD'
      },
      {
        path = '/admin.nsf',
        method = 'HEAD'
      },
      {
        path = '/agentrunner.nsf',
        method = 'HEAD'
      },
      {
        path = '/alog.nsf',
        method = 'HEAD'
      },
      {
        path = '/a_domlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/bookmark.nsf',
        method = 'HEAD'
      },
      {
        path = '/busytime.nsf',
        method = 'HEAD'
      },
      {
        path = '/catalog.nsf',
        method = 'HEAD'
      },
      {
        path = '/certa.nsf',
        method = 'HEAD'
      },
      {
        path = '/certlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/certsrv.nsf',
        method = 'HEAD'
      },
      {
        path = '/chatlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/clbusy.nsf',
        method = 'HEAD'
      },
      {
        path = '/cldbdir.nsf',
        method = 'HEAD'
      },
      {
        path = '/clusta4.nsf',
        method = 'HEAD'
      },
      {
        path = '/collect4.nsf',
        method = 'HEAD'
      },
      {
        path = '/da.nsf',
        method = 'HEAD'
      },
      {
        path = '/dba4.nsf',
        method = 'HEAD'
      },
      {
        path = '/dclf.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASAppDesign.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog01.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog02.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog03.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog04.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog05.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEASLog.nsf',
        method = 'HEAD'
      },
      {
        path = '/decsadm.nsf',
        method = 'HEAD'
      },
      {
        path = '/decslog.nsf',
        method = 'HEAD'
      },
      {
        path = '/DEESAdmin.nsf',
        method = 'HEAD'
      },
      {
        path = '/dirassist.nsf',
        method = 'HEAD'
      },
      {
        path = '/doladmin.nsf',
        method = 'HEAD'
      },
      {
        path = '/domadmin.nsf',
        method = 'HEAD'
      },
      {
        path = '/domcfg.nsf',
        method = 'HEAD'
      },
      {
        path = '/domguide.nsf',
        method = 'HEAD'
      },
      {
        path = '/domlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/dspug.nsf',
        method = 'HEAD'
      },
      {
        path = '/events4.nsf',
        method = 'HEAD'
      },
      {
        path = '/events5.nsf',
        method = 'HEAD'
      },
      {
        path = '/events.nsf',
        method = 'HEAD'
      },
      {
        path = '/event.nsf',
        method = 'HEAD'
      },
      {
        path = '/homepage.nsf',
        method = 'HEAD'
      },
      {
        path = '/iNotes/Forms5.nsf/$DefaultNav',
        method = 'HEAD'
      },
      {
        path = '/jotter.nsf',
        method = 'HEAD'
      },
      {
        path = '/leiadm.nsf',
        method = 'HEAD'
      },
      {
        path = '/leilog.nsf',
        method = 'HEAD'
      },
      {
        path = '/leivlt.nsf',
        method = 'HEAD'
      },
      {
        path = '/log4a.nsf',
        method = 'HEAD'
      },
      {
        path = '/log.nsf',
        method = 'HEAD'
      },
      {
        path = '/l_domlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/mab.nsf',
        method = 'HEAD'
      },
      {
        path = '/mail10.box',
        method = 'HEAD'
      },
      {
        path = '/mail1.box',
        method = 'HEAD'
      },
      {
        path = '/mail2.box',
        method = 'HEAD'
      },
      {
        path = '/mail3.box',
        method = 'HEAD'
      },
      {
        path = '/mail4.box',
        method = 'HEAD'
      },
      {
        path = '/mail5.box',
        method = 'HEAD'
      },
      {
        path = '/mail6.box',
        method = 'HEAD'
      },
      {
        path = '/mail7.box',
        method = 'HEAD'
      },
      {
        path = '/mail8.box',
        method = 'HEAD'
      },
      {
        path = '/mail9.box',
        method = 'HEAD'
      },
      {
        path = '/mail.box',
        method = 'HEAD'
      },
      {
        path = '/msdwda.nsf',
        method = 'HEAD'
      },
      {
        path = '/mtatbls.nsf',
        method = 'HEAD'
      },
      {
        path = '/mtstore.nsf',
        method = 'HEAD'
      },
      {
        path = '/names.nsf',
        method = 'HEAD'
      },
      {
        path = '/nntppost.nsf',
        method = 'HEAD'
      },
      {
        path = '/nntp/nd000001.nsf',
        method = 'HEAD'
      },
      {
        path = '/nntp/nd000002.nsf',
        method = 'HEAD'
      },
      {
        path = '/nntp/nd000003.nsf',
        method = 'HEAD'
      },
      {
        path = '/ntsync45.nsf',
        method = 'HEAD'
      },
      {
        path = '/perweb.nsf',
        method = 'HEAD'
      },
      {
        path = '/qpadmin.nsf',
        method = 'HEAD'
      },
      {
        path = '/quickplace/quickplace/main.nsf',
        method = 'HEAD'
      },
      {
        path = '/reports.nsf',
        method = 'HEAD'
      },
      {
        path = '/sample/siregw46.nsf',
        method = 'HEAD'
      },
      {
        path = '/schema50.nsf',
        method = 'HEAD'
      },
      {
        path = '/setupweb.nsf',
        method = 'HEAD'
      },
      {
        path = '/setup.nsf',
        method = 'HEAD'
      },
      {
        path = '/smbcfg.nsf',
        method = 'HEAD'
      },
      {
        path = '/smconf.nsf',
        method = 'HEAD'
      },
      {
        path = '/smency.nsf',
        method = 'HEAD'
      },
      {
        path = '/smhelp.nsf',
        method = 'HEAD'
      },
      {
        path = '/smmsg.nsf',
        method = 'HEAD'
      },
      {
        path = '/smquar.nsf',
        method = 'HEAD'
      },
      {
        path = '/smsolar.nsf',
        method = 'HEAD'
      },
      {
        path = '/smtime.nsf',
        method = 'HEAD'
      },
      {
        path = '/smtpibwq.nsf',
        method = 'HEAD'
      },
      {
        path = '/smtpobwq.nsf',
        method = 'HEAD'
      },
      {
        path = '/smtp.box',
        method = 'HEAD'
      },
      {
        path = '/smtp.nsf',
        method = 'HEAD'
      },
      {
        path = '/smvlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/srvnam.htm',
        method = 'HEAD'
      },
      {
        path = '/statmail.nsf',
        method = 'HEAD'
      },
      {
        path = '/statrep.nsf',
        method = 'HEAD'
      },
      {
        path = '/stauths.nsf',
        method = 'HEAD'
      },
      {
        path = '/stautht.nsf',
        method = 'HEAD'
      },
      {
        path = '/stconfig.nsf',
        method = 'HEAD'
      },
      {
        path = '/stconf.nsf',
        method = 'HEAD'
      },
      {
        path = '/stdnaset.nsf',
        method = 'HEAD'
      },
      {
        path = '/stdomino.nsf',
        method = 'HEAD'
      },
      {
        path = '/stlog.nsf',
        method = 'HEAD'
      },
      {
        path = '/streg.nsf',
        method = 'HEAD'
      },
      {
        path = '/stsrc.nsf',
        method = 'HEAD'
      },
      {
        path = '/userreg.nsf',
        method = 'HEAD'
      },
      {
        path = '/vpuserinfo.nsf',
        method = 'HEAD'
      },
      {
        path = '/webadmin.nsf',
        method = 'HEAD'
      },
      {
        path = '/web.nsf',
        method = 'HEAD'
      },
      {
        path = '/.nsf/../winnt/win.ini',
        method = 'HEAD'
      },
      {
        path = '/icons/ecblank.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Lotus Domino'
      }
    }
  });

------------------------------------------------
----              MICROSOFT                 ----
------------------------------------------------
table.insert(fingerprints, {
    category = 'microsoft',
    probes = {
      {
        path = '/_layouts/images/helpicon.gif',
        method = 'HEAD'
      },
      {
        path = '/Pages/Default.aspx',
        method = 'HEAD'
      },
      {
        path = '/PublishingImages/NewsArticleImage.jpg',
        method = 'HEAD'
      },
      {
        path = '/_admin/operations.aspx',
        method = 'HEAD'
      },
      {
        path = '/_app_bin',
        method = 'HEAD'
      },
      {
        path = '/_controltemplates',
        method = 'HEAD'
      },
      {
        path = '/_layouts',
        method = 'HEAD'
      },
      {
        path = '/_layouts/viewlsts.aspx',
        method = 'HEAD'
      },
      {
        path = '/forms/allitems.aspx',
        method = 'HEAD'
      },
      {
        path = '/forms/webfldr.aspx',
        method = 'HEAD'
      },
      {
        path = '/forms/mod-view.aspx',
        method = 'HEAD'
      },
      {
        path = '/forms/my-sub.aspx',
        method = 'HEAD'
      },
      {
        path = '/pages/categoryresults.aspx',
        method = 'HEAD'
      },
      {
        path = '/categories/viewcategory.aspx',
        method = 'HEAD'
      },
      {
        path = '/sitedirectory',
        method = 'HEAD'
      },
      {
        path = '/editdocs.aspx',
        method = 'HEAD'
      },
      {
        path = '/workflowtasks/allitems.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/tasks/',
        method = 'HEAD'
      },
      {
        path = '/categories/allcategories.aspx',
        method = 'HEAD'
      },
      {
        path = '/categories/SOMEOTHERDIR/allcategories.aspx',
        method = 'HEAD'
      },
      {
        path = '/mycategories.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/',
        method = 'HEAD'
      },
      {
        path = '/lists/allitems.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/default.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/allposts.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/archive.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/byauthor.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/calendar.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/mod-view.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/myposts.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/my-sub.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/allcomments.aspx',
        method = 'HEAD'
      },
      {
        path = '/lists/mycomments.aspx',
        method = 'HEAD'
      },
      {
        path = '/_layouts/userdisp.aspx',
        method = 'HEAD'
      },
      {
        path = '/_layouts/help.aspx',
        method = 'HEAD'
      },
      {
        path = '/_layouts/download.aspx',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'MS Sharepoint'
      }
    }
  });

table.insert(fingerprints, {
    category = 'microsoft',
    probes = {
      {
        path = '/projectserver/Home/HomePage.asp',
        method = 'HEAD'
      },
      {
        path = '/projectserver/images/branding.gif',
        method = 'HEAD'
      },
      {
        path = '/projectserver/images/pgHome.gif',
        method = 'HEAD'
      },
      {
        path = '/projectserver/images/pgTask.gif',
        method = 'HEAD'
      },
      {
        path = '/projectserver/Tasks/Taskspage.asp',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'MS Project Server'
      }
    }
  });

table.insert(fingerprints, {
    category = 'microsoft',
    probes = {
      {
        path = '/exchweb/bin/auth/owalogon.asp',
        method = 'HEAD'
      },
      {
        path = '/images/outlook.jpg',
        method = 'HEAD'
      },
      {
        path = '/owa/8.1.375.2/themes/base/lgntopl.gif',
        method = 'HEAD'
      },
      {
        path = '/owa/',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Outlook Web Access'
      }
    }
  });

table.insert(fingerprints, {
    category = 'microsoft',
    probes = {
      {
        path = '/tsweb/',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Remote Desktop Web Connection'
      }
    }
  });

table.insert(fingerprints, {
    category = 'microsoft',
    probes = {
      {
        path = '/reportserver/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Microsoft SQL Report Service'
      }
    }
  });
------------------------------------------------
----         NETWORK EQUIPMENT              ----
------------------------------------------------
-- Routers, switches, etc
table.insert(fingerprints, {
    category = 'network',
    probes = {
      {
        path = '/',
        method = 'GET'
      },
    },
    matches = {
      {
        match = 'realm="WRT54G"',
        output = 'Linksys WRT54g Wireless Router'
      }
    }
  });

table.insert(fingerprints, {
    category = 'network',
    probes = {
      {
        path = '/HW_logo.html',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Huawei HG 530'
      }
    }
  });

table.insert(fingerprints, {
    category = 'network',
    probes = {
      {
        path = '/icons/icon_set_up_2701XX_01.gif',
        method = 'HEAD'
      },
      {
        path = '/icons/icon_homeportal_2701XX.gif',
        method = 'HEAD'
      },
      {
        path = '/es/images/nav_sl_home_network_01.gif',
        method = 'HEAD'
      },
      {
        path = '/en/images/nav_sl_home_network_01.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '2WIRE 2701HG'
      }
    }
  });

table.insert(fingerprints, {
    category = 'network',
    probes = {
      {
        path = '/images/stxx__xl.gif',
        method = 'HEAD'
      },
      {
        path = '/images/bbc__xl.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Thomson TG585'
      }
    }
  });

-- HNAP Devices
table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/HNAP1/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<ModelDescription>(.-)</ModelDescription>',
        output = '\\1'
      }
    }
  });

------------------------------------------------
----               ATTACKS                  ----
------------------------------------------------
-- These will search for and possibly exploit vulnerabilities.

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/sdk/../../../../../../../etc/vmware/hostd/vmInventory.xml',
        method = 'GET',
        nopipeline = true
      },
      {
        path = '/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/vmware/hostd/vmInventory.xml',
        method = 'GET',
        nopipeline = true
      }
    },
    matches = {
      {
        match = '<ConfigRoot>',
        output = 'Path traversal in VMWare (CVE-2009-3733)'
      },
      {
        match = '',
        output = 'Possible path traversal in VMWare (CVE-2009-3733)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/../../../../../../../../../../etc/passwd',
        method = 'GET',
        nopipeline = true
      },
      {
        path = '/../../../../../../../../../../boot.ini',
        method = 'GET',
        nopipeline = true
      }
    },
    matches = {
      {
        match = 'root:',
        output = 'Simple path traversal in URI (Linux)'
      },
      {
        match = 'boot loader',
        output = 'Simple path traversal in URI (Windows)'
      },
      {
        match = '',
        output = 'Possible path traversal in URI'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/.htaccess',
        method = 'GET'
      },
      {
        path = '/.htpasswd',
        method = 'GET'
      }
    },
    matches = {
      -- We look for a '200 OK' message on this one, because most Apache servers return an access denied
      {
        match = '200 OK',
        output = 'Incorrect permissions on .htaccess or .htpasswd files'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/_vti_bin/',
        method = 'GET'
      },
      {
        path = '/_vti_cnf/',
        method = 'GET'
      },
      {
        path = '/_vti_log/',
        method = 'GET'
      },
      {
        path = '/_vti_pvt/',
        method = 'GET'
      },
      {
        path = '/_vti_txt/',
        method = 'GET'
      },
      {
        path = '/postinfo.html'
      },
      {
        path = '/_vti_bin/_vti_aut/author.dll'
      },
      {
        path = '/_vti_bin/_vti_aut/author.exe'
      },
      {
        path = '/_vti_bin/_vti_aut/dvwssr.dll'
      },
      {
        path = '/_vti_bin/_vti_adm/admin.dll'
      },
      {
        path = '/_vti_bin/_vti_adm/admin.exe'
      },
      {
        path = '/_vti_bin/fpcount.exe?Page=default.asp|Image=3'
      },
      {
        path = '/_vti_bin/shtml.dll'
      },
      {
        path = '/_vti_bin/shtml.exe'
      },
      {
        path = '/_vti_pvt/_x_todo.htm'
      },
      {
        path = '/_vti_pvt/_x_todoh.htm'
      },
      {
        path = '/_vti_pvt/access.cnf'
      },
      {
        path = '/_vti_pvt/administrator.pwd'
      },
      {
        path = '/_vti_pvt/administrators.pwd'
      },
      {
        path = '/_vti_pvt/authors.pwd'
      },
      {
        path = '/_vti_pvt/bots.cnf'
      },
      {
        path = '/_vti_pvt/botinfs.cnf'
      },
      {
        path = '/_vti_pvt/deptodoc.btr'
      },
      {
        path = '/_vti_pvt/doctodep.btr'
      },
      {
        path = '/_vti_pvt/frontpg.lck'
      },
      {
        path = '/_vti_pvt/linkinfo.cnf'
      },
      {
        path = '/_vti_pvt/service.cnf'
      },
      {
        path = '/_vti_pvt/service.grp'
      },
      {
        path = '/_vti_pvt/service.lck'
      },
      {
        path = '/_vti_pvt/service.pwd'
      },
      {
        path = '/_vti_pvt/Service.stp'
      },
      {
        path = '/_vti_pvt/services.cnf'
      },
      {
        path = '/_vti_pvt/services.org'
      },
      {
        path = '/_vti_pvt/structure.cnf'
      },
      {
        path = '/_vti_pvt/svcacl.cnf'
      },
      {
        path = '/_vti_pvt/users.pwd'
      },
      {
        path = '/_vti_pvt/uniqueperm.cnf'
      },
      {
        path = '/_vti_pvt/writeto.cnf'
      },
    },
    matches = {
      {
        match = '200',
        output = 'Frontpage file or folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/.svn/',
        method = 'GET'
      },
      {
        path = '/.svn/text-base/.htaccess.svn-base',
        method = 'GET'
      },
      {
        path = '/.svn/text-base/.htpasswd.svn-base',
        method = 'GET'
      },
      {
        path = '/.svn/text-base/Web.config.svn-base',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'Subversion folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/.git/HEAD',
        method = 'GET'
      },
    },
    matches = {
      {
        match = 'ref: refs',
        output = 'Git folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/.hg/requires',
        method = 'GET'
      },
    },
    matches = {
      {
        match = 'revlogv1',
        output = 'Mercurial folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/.bzr/README',
        method = 'GET'
      },
    },
    matches = {
      {
        match = 'This is a Bazaar',
        output = 'Bazaar folder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/downloadFile.php',
        method = 'GET'
      },
      {
        path = '/BackupConfig.php',
        method = 'GET'
      }
    },
    matches = {
      {
        output = 'NETGEAR WNDAP350 2.0.1 to 2.0.9 potential file download and SSH root password disclosure'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/cwhp/auditLog.do?file=..\\..\\..\\..\\..\\..\\..\\boot.ini',
        method = 'GET'
      },
      {
        path = '/cwhp/auditLog.do?file=..\\..\\..\\..\\..\\..\\..\\Program%20Files\\CSCOpx\\MDC\\Tomcat\\webapps\\triveni\\WEB-INF\\classes\\schedule.properties',
        method = 'GET'
      },
      {
        path = '/cwhp/auditLog.do?file=..\\..\\..\\..\\..\\..\\..\\Program%20Files\\CSCOpx\\lib\\classpath\\com\\cisco\\nm\\cmf\\dbservice2\\DBServer.properties',
        method = 'GET'
      },
      {
        path = '/cwhp/auditLog.do?file=..\\..\\..\\..\\..\\..\\..\\Program%20Files\\CSCOpx\\log\\dbpwdChange.log',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'boot loader',
        output = 'CiscoWorks (CuOM 8.0 and 8.5) Directory traversal (CVE-2011-0966) (Windows)'
      },
      {
        match = '',
        output = 'Possible CiscoWorks (CuOM 8.0 and 8.5) Directory traversal (CVE-2011-0966) (Windows)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/var/mobile/Library/AddressBook/AddressBook.sqlitedb',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Possible iPhone/iPod/iPad generic file sharing app Directory Traversal (iOS)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/Info.live.htm',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'Possible DD-WRT router Information Disclosure (OSVDB 70230)'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/CuteSoft_Client/CuteEditor/Load.ashx?type=image&file=../../../web.config',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'Cute Editor ASP.NET Remote File Disclosure ( CVE 2009-4665 )'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/plugins/PluginController.php?path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini%00',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'OrangeHRM 2.6.3 Local File Inclusion '
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/tiki-listmovies.php?movie=../../../../../../etc/passwd%001234',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'TikiWiki < 1.9.9 Directory Traversal Vulnerability'
      }
    }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&version=1576&cid=20',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '2.0.11</title',
        output = 'Joomla JCE Extension 2.0.11 Remote Code Execution vulnerability'
      },
      {
        match = '2.0.12</title',
        output = 'Joomla JCE Extension 2.0.12 Remote Code Execution vulnerability'
      },
      {
        match = '2.0.13</title',
        output = 'Joomla JCE Extension 2.0.13 Remote Code Execution vulnerability'
      },
      {
        match = '2.0.14</title',
        output = 'Joomla JCE Extension 2.0.14 Remote Code Execution vulnerability'
      },
      {
        match = '2.0.15</title',
        output = 'Joomla JCE Extension 2.0.11 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.10</title',
        output = 'Joomla JCE Extension 1.5.7.10 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.10</title',
        output = 'Joomla JCE Extension 1.5.7.10 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.11</title',
        output = 'Joomla JCE Extension 1.5.7.11 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.12</title',
        output = 'Joomla JCE Extension 1.5.7.12 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.13</title',
        output = 'Joomla JCE Extension 1.5.7.13 Remote Code Execution vulnerability'
      },
      {
        match = '1.5.7.14</title',
        output = 'Joomla JCE Extension 1.5.7.14 Remote Code Execution vulnerability'
      }
   }
  });

table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/d41d8cd98f00b204e9800998ecf8427e.php',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'Seagate BlackArmorNAS 110/220/440 Administrator Password Reset Vulnerability'
      }
    }
  });

-- HNAP Authentication Bypass
table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0',
        method = 'GET'
      }
    },
    matches = {
      {
        dontmatch = '<a href="http://www%.dlink%.com"',
        match = '^HTTP/1.[01] 200 OK\r\n.*Server: Embedded HTTP Server',
        output = 'D-Link Router Vulnerable to Authentication Bypass',
      },
      {
        dontmatch = '<a href="http://www%.dlink%.com"',
        match = '^HTTP/1.[01] 200 OK\r\n.*Server: Virtual Web 0.9',
        output = 'D-Link Router Vulnerable to Authentication Bypass',
      },
    }
  });

-- Rompager info disclosure
table.insert(fingerprints, {
    category = 'attacks',
    probes = {
      {
        path = '/rom-0',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'dbgarea',
        output = 'RomPager Embedded Web Server information disclosure (CVE-2014-4019)'
      },
      {
        match = 'spt%.dat',
        output = 'RomPager Embedded Web Server information disclosure (CVE-2014-4019)'
      },
      {
        match = 'autoexec%.net',
        output = 'RomPager Embedded Web Server information disclosure (CVE-2014-4019)'
      },
    }
  });

------------------------------------------------
----        Open Source CMS checks          ----
------------------------------------------------

-- Broad wordpress version identification
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/wp-login.php'
      },
      {
        path = '/wordpress/wp-login.php'
      },
      {
        path = '/blog/wp-login.php'
      },
      {
        path = '/administrator/wp-login.php'
      },
      {
        path = '/weblog/wp-login.php'
      }
    },
    matches = {
      {
        match = 'ver=20080708',
        output = 'WordPress 2.6.x found'
      },
      {
        match = 'ver=20081210',
        output = 'WordPress 2.7.x found'
      },
      {
        match = 'ver=20090514',
        output = 'WordPress 2.8.x found'
      },
      {
        match = 'ver=20091217',
        output = 'WordPress 2.9.x found'
      },
      {
        match = 'ver=20100601',
        output = 'WordPress 3.0.x found'
      },
      {
        output = 'Wordpress login page.'
      }
    }
  });

-- ZenCart version detection
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/docs/'
      },
      {
        path = '/store/docs/'
      },
      {
        path = '/zencart/docs/'
      },
      {
        path = '/cart/docs/'
      }
    },
    matches = {
      {
        match = '.*">Changelog for v(%d-%..-) %(changed files%)</a>',
        output = 'ZenCart, version \\1'
      }
    }
  });

-- Broad phpBB versions
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/docs/CHANGELOG.html'
      },
      {
        path = '/forum/docs/CHANGELOG.html'
      },
      {
        path = '/forums/docs/CHANGELOG.html'
      },
      {
        path = '/board/docs/CHANGELOG.html'
      },
      {
        path = '/boards/docs/CHANGELOG.html'
      }
    },
    matches = {
      {
        match = 'Changes since (%d-%..-)</a>',
        output = 'phpBB version slightly newer than \\1'
      },
      {
        match = '<meta name="description" content="phpBB (%d-%..-) Changelog"',
        output = 'phpBB, version \\1'
      },
      {
        match = 'Changes since (%d)',
        output = 'phpBB versioning \\1'
      },
    }
  });

-- tinymce / changelog
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/changelog.txt'
      },
      {
        path = '/tinymce/changelog.txt'
      },
    },
    matches = {
      {
        match = 'Version (.-) ',
        output = 'Version \\1'
      },
      {
        output = 'Interesting, a changelog.'
      }
    }
  });

-- interesting README  files
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/readme.html'
      },
      {
        path = '/pligg/readme.html'
      },
      {
        path = '/digg/readme.html'
      },
      {
        path = '/news/readme.html'
      },
    },
    matches = {
      {
        match = '<h1>Pligg Content Management System</h1>%s*<h2>Version (.-)</h2>',
        output = 'Pligg version \\1'
      },
      {
        match = '<br /> Version (.-)\n',
        output = 'WordPress version \\1'
      },
      {
        output = 'Interesting, a readme.'
      }
    }
  });

-- They're kind enough to tell us in the meta tags (used for the author's stats)
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/'
      },
      {
        path = '/forum/'
      },
      {
        path = '/site/'
      },
      {
        path = '/website/'
      },
      {
        path = '/store/'
      },
      {
        path = '/webstore/'
      },
      {
        path = '/comic/'
      },
      {
        path = '/wiki/'
      },
      {
        path = '/mediawiki/'
      },
      {
        path = '/Mediawiki/'
      },
      {
        path = '/MediaWiki/'
      },
      {
        path = '/wordpress/'
      },
      {
        path = '/blog/'
      },
      {
        path = '/cms/'
      },
      {
        path = '/comiccms/'
      },
      {
        path = '/weblog/'
      },
      {
        path = '/joomla/'
      },
      {
        path = '/administrator/'
      },
      {
        path = '/openx/www/admin/index.php'
      },
      {
        path = '/www/admin/index.php'
      },
      {
        path = '/ads/www/admin/index.php'
      },
      {
        path = '/adserver/www/admin/index.php'
      },
      {
        path = '/splashfrog/'
      },
      {
        path = '/pligg/'
      },
      {
        path = '/vanilla/'
      },
      {
        path = '/vanillaforum/'
      },
      {
        path = '/vanillaforums/'
      },
      {
        path = '/statusnet/'
      },
      {
        path = '/xoda/'
      },
      {
        path = '/trac/'
      },
      {
        path = '/lime/'
      },
      {
        path = '/survey/'
      },
      {
        path = '/limesurvey/'
      },
      {
        path = '/openvbx/'
      },
      {
        path = '/getsimple/'
      },
      {
        path = '/ecoder/'
      },
    },
    matches = {
      {
        match = '<meta name="generator" content="Bluefish 2.0.1" ',
        output = '\\1'
      },
      {
        match = '<h1>ecoder v(.-)</h1>',
        output = 'ecoder v\\1'
      },
      {
        match = '<a href="http://www.splashfrog.com" target="_blank">Splash Frog WMS v(.-)</a>',
        output = 'Splash Frog WMS v\\1'
      },
      {
        match = '<a href="http://status.net/">StatusNet</a> microblogging software, version (.-),',
        output = 'StatusNet v\\1'
      },
      {
        match = '<script src=".*/applications/vanilla/js/options.js%?v%=(.-)" type="text/javascript">',
        output = 'Vanilla Forums v\\1'
      },
      {
        match = 'about"><strong>Trac (.-)</strong></a>',
        output = 'Trac version \\1'
      },
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/cmspages.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '2Point Solutions CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/sc_webcat/ecat/cms_view.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Webcat'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/kbcat.cgi',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ActivDesk'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/workorder/FileDownload.jsp',
        method = 'GET'
      },
      {
        path = '/sd/workorder/FileDownload.jsp',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '500',
        output = 'ManageEngine Support Center Plus'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/sections/reference.inc.php',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'BrewBlogger'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/store.php?action=view_cart',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'AiCart'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/catalog/main.php?cat_id=',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '200',
        output = 'Catalog Builder'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/index.php?cat_id=1',
        method = 'GET'
      }
    },
    matches = {
      {
        match = 'powered by CubeCart',
        output = 'CubeCart'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/forum_answer.php?que_id=1',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Guru JustAnswer'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/templates1/view_product.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'HB ECommerce'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/escort-profile.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'First Escort Marketing CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/pages/indexheader.php',
        method = 'HEAD'
      },
      {
        path = '/pages/searcher.php',
        method = 'HEAD'
      },
      {
        path = '/pages/indexviewentry.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Green Pants CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/tinymcpuk/filemanager/browser.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CMS Lokomedia'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/admin/libraries/ajaxfilemanager/ajaxfilemanager.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Log1 CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/leftmenubody.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Quicktech'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/dsp_page.cfm',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Alcassofts SOPHIA CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/zikula/index.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Zikula CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/system/admin/header.php',
        method = 'HEAD'
      },
      {
        path = '/system/admin/comments_items.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Habari Blog'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/scripts/fckeditor/editor/filemanager/connectors/test.html',
        method = 'HEAD'
      },
      {
        path = '/scripts/fckeditor/editor/filemanager/connectors/uploadtest.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Digitalus CMS/FCKEditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/fckeditor/editor/filemanager/connectors/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'phpmotion/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/fckeditor/editor/filemanager/upload/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Geeklog/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'OpenCart/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/fckeditor/editor/filemanager/connectors/php/config.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'DM File Manager/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/cfm/connector.cfm',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/lasso/connector.lasso',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/perl/connector.cgi',
        method = 'HEAD'
      },
      {
        path = '/includes/FCKeditor/editor/filemanager/browser/default/connectors/py/connector.py',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'PHPnuke/Remote File Download'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/FCKEditor/editor/filemanager/browser/default/connectors/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'EgO or osCMax/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/admin/includes/tiny_mce/plugins/tinybrowser/upload.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CompactCMS or B-Hind CMS/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/Backstage/Components/FreeTextBox/ftb.imagegallery.aspx',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Luftguitar CMS/File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/_plugin/fckeditor/editor/filemanager/connectors/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'SweetRice/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/html/news_fckeditor/editor/filemanager/upload/php/upload.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'cardinalCms/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/fckeditor/editor/filemanager/connectors/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'LightNEasy/FCKeditor File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/admin/includes/FCKeditor/editor/filemanager/upload/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ASP Simple Blog / FCKeditor File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/uploadsnaps.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'ZeeMatri/File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/upload/includes/js/files/upload.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Digital College/File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/tinybrowser/upload.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Tinybrowser Remote File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/editor/editor/filemanager/upload/test.html',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Tadbir / File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/photogallery_open.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Heaven Soft CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/Providers/HtmlEditorProviders/Fck/fcklinkgallery.aspx',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'DotNetNuke / File Upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/assetmanager/assetmanager.asp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Asset Manager/Remote File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/Final/login/ava_upl.php',
        method = 'HEAD'
      },
      {
        path = '/Final/login/ava_upl2.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'CH-CMS'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/spaw/demo.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'SpawCMS/Remote File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/admin/jscript/upload.php',
        method = 'HEAD'
      },
      {
        path = '/admin/jscript/upload.html',
        method = 'HEAD'
      },
      {
        path = '/admin/jscript/upload.pl',
        method = 'HEAD'
      },
      {
        path = '/admin/jscript/upload.asp',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Lizard Cart/Remote File upload'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/databases/acidcat_3.mdb',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Acidcat CMS Database'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/mdb-database/dblog.mdb',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'dBlog Database'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/db/users.mdb',
        method = 'HEAD'
      },
      {
        path = '/db/'
      }
    },
    matches = {
      {
        match = '',
        output = 'BlogWorx Database'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/infusions/avatar_studio/avatar_studio.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'PHP-Fusion Mod avatar_studio'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/bnnr.php',
        method = 'HEAD'
      },
      {
        path = '/vb/bnnr.php',
        method = 'HEAD'
      },
      {
        path = '/forum/bnnr.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'vBulletin ads_saed'
      }
    }
  });

table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/weblink_cat_list.php',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'WHMCompleteSolution CMS'
      }
    }
  });

-- Drupal signatures
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = ' src="/sites/all/themes/',
        output = 'Drupal signature'
      },
      {
        match = ' src="/sites/all/modules/',
        output = 'Drupal signature'
      },
      {
        match = ' href="/sites/all/themes/',
        output = 'Drupal signature'
      },
      {
        match = 'jQuery.extend(Drupal.settings,',
        output = 'Drupal signature'
      }
    }
  });

-- Drupal files
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/UPGRADE.txt'
      },
      {
        path = '/INSTALL.txt'
      },
      {
        path = '/MAINTENERS.txt'
      },
      {
        path = '/INSTALL.mysql.txt'
      },
      {
        path = '/INSTALL.pgsql.txt'
      },
      {
        path = '/update.php'
      }
    },
    matches = {
      {
        match = 'Drupal ',
        output = 'Drupal file'
      }
    }
  });

-- Joomla! version
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/language/en-GB/en-GB.xml'
      }
    },
    matches = {
      {
        match = '<version>(.-)</version>',
        output = 'Joomla! '
      }
    }
  });

-- Joomla!
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/htaccess.txt'
      },
      {
        path = '/templates/system/css/toolbar.css'
      },
      {
        path = '/templates/beez/css/template_rtl.css'
      }
    },
    matches = {
      {
        match = 'Joomla!',
        output = 'Joomla!'
      }
    }
  });

-- Drupal changelog
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/CHANGELOG.txt'
      }
    },
    matches = {
      {
        match = 'Drupal (%d..-),',
        output = 'Drupal v1'
      }
    }
  });

-- Moodle
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/pix/moodlelogo.gif',
        method = 'HEAD'
      },
      {
        path = '/admin/environment.xml',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'Moodle files'
      }
    }
  });

-- typo3
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/typo3/index.php',
        method = 'GET'
      },
      {
        path = '/typo3/README.txt',
        method = 'GET'
      },
      {
        path = '/t3lib/README.txt',
        method = 'GET'
      },
      {
        path = '/typo3/sysext/t3skin/images/login/typo3logo-white-greyback.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = 'Login to the TYPO3',
        output = 'Typo3 login page'
      },
      {
        match = 'TYPO3 Backend Administration',
        output = 'Typo3 readme file'
      },
      {
        match = 'TYPO3 Library',
        output = 'Typo3 Library readme'
      },
      {
        match = '',
        output = 'Typo3 Installation'
      },
    }
  });

------------------------------------------------
----                 MAIL                   ----
------------------------------------------------

-- SquirrelMail
table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/squirrelmail/src/login.php',  -- Might return login page with version info
        method = 'GET'
      },
      {
        path = '/webmail/src/login.php',  -- Might return login page with version info
        method = 'GET'
      },
      {
        path = '/src/login.php',  -- Might return login page with version info
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<small>([^<]*)<br />',  -- version extraction (squirrelMail)
        output = '\\1'
      },
      {
        match = 'squirrelmail',
        output = 'SquirrelMail'
      }
    }
  });

-- SquirrelMail files
table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/squirrelmail/images/sm_logo.png',  -- Standard logo file
        method = 'HEAD'
      },
      {
        path = '/webmail/images/sm_logo.png',   -- Standard logo file
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'SquirrelMail'
      }
    }
  });

-- RoundCube
table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/',
        method = 'GET'
      },
      {
        path = '/program/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of /program</title>',
        output = 'RoundCube (Directory listing)'
      },
      {
        match = 'rcube_webmail', -- RoundCube
        output = 'RoundCube'
      },
    }
  });

-- RoundCube file
table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/skins/default/images/roundcube_logo.png',  -- Standard logo file
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'RoundCube'
      }
    }
  });

------------------------------------------------
----           UNCATEGORIZED                ----
------------------------------------------------

table.insert(fingerprints, {
    category = 'uncategorized',
    probes = {
      {
        path = '/archive/flash:home/html/images/Cisco_logo.gif',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'Cisco SDM'
      }
    }
  });

table.insert(fingerprints, {
    category = 'uncategorized',
    probes = {
      {
        path = '/Default?MAIN=DEVICE',
        method = 'HEAD'
      },
      {
        path = '/TopAccess/images/RioGrande/Rio_PPC.gif',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = 'TopAccess Toshiba e-Studio520'
      }
    }
  });

table.insert(fingerprints, {
    category = 'uncategorized',
    probes = {
      {
        path = '/jwsappmngr.jnlp',
        method = 'HEAD'
      },
      {
        path = '/nfdesktop.jnlp',
        method = 'HEAD'
      },
      {
        path = '/nfservlets/servlet/SPSRouterServlet/',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'netForensics'
      }
    }
  });

table.insert(fingerprints, {
    category = 'uncategorized',
    probes = {
      {
        path = '/na_admin/styles/dfm.css',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = 'NetworkAppliance NetApp Release 6.5.3P4'
      }
    }
  });

------------------------------------------------
----    MISCELLANEOUS ITEMS OF INTEREST     ----
------------------------------------------------

-- Moodle files
table.insert(fingerprints, {
    category = 'miscellaneous',
    probes = {
      {
        path = '/lib/db/install.xml'
      },
      {
        path = '/lib/thirdpartylibs.xml'
      },
      {
        path = '/local/readme.txt'
      }
    },
    matches = {
      {
        match = 'XMLDB file for core Moodle tables',
        output = 'Moodle db installation file'
      },
      {
        match = '<libraries>',
        output = 'Moodle thirdpartylibs.xml'
      },
      {
        match = 'This file is part of Moodle',
        output = 'Moodle local/readme.txt'
      }
    }
  });

-- interesting README  files
table.insert(fingerprints, {
    category = 'miscellaneous',
    probes = {
      {
        path = '/README'
      },
      {
        path = '/README.txt'
      },
      {
        path = '/xoda/README'
      },
      {
        path = '/docs/README'
      },
      {
        path = '/documents/README'
      },
      {
        path = '/dms/README'
      },
      {
        path = '/status/README'
      },
      {
        path = '/statusnet/README'
      },
      {
        path = '/twitter/README'
      },
    },
    matches = {
      {
        match = 'StatusNet (.-) ',
        output = 'StatusNet README version \\1'
      },
      {
        match = 'XODA.*Changelog%s---------%s(%d.-):',
        output = 'XODA \\1'
      },
      {
        output = 'Interesting, a readme.'
      }
    }
  });

table.insert(fingerprints, {
    category = 'miscellaneous',
    probes = {
      {
        path = '/0/',
        method = 'GET'
      },
      {
        path = '/1/',
        method = 'GET'
      },
      {
        path = '/2/',
        method = 'GET'
      },
      {
        path = '/3/',
        method = 'GET'
      },
      {
        path = '/4/',
        method = 'GET'
      },
      {
        path = '/5/',
        method = 'GET'
      },
      {
        path = '/6/',
        method = 'GET'
      },
      {
        path = '/7/',
        method = 'GET'
      },
      {
        path = '/8/',
        method = 'GET'
      },
      {
        path = '/9/',
        method = 'GET'
      },
      {
        path = '/10/',
        method = 'GET'
      },
      {
        path = '/a/',
        method = 'GET'
      },
      {
        path = '/b/',
        method = 'GET'
      },
      {
        path = '/c/',
        method = 'GET'
      },
      {
        path = '/d/',
        method = 'GET'
      },
      {
        path = '/e/',
        method = 'GET'
      },
      {
        path = '/f/',
        method = 'GET'
      },
      {
        path = '/g/',
        method = 'GET'
      },
      {
        path = '/h/',
        method = 'GET'
      },
      {
        path = '/i/',
        method = 'GET'
      },
      {
        path = '/j/',
        method = 'GET'
      },
      {
        path = '/k/',
        method = 'GET'
      },
      {
        path = '/l/',
        method = 'GET'
      },
      {
        path = '/m/',
        method = 'GET'
      },
      {
        path = '/n/',
        method = 'GET'
      },
      {
        path = '/o/',
        method = 'GET'
      },
      {
        path = '/p/',
        method = 'GET'
      },
      {
        path = '/q/',
        method = 'GET'
      },
      {
        path = '/r/',
        method = 'GET'
      },
      {
        path = '/s/',
        method = 'GET'
      },
      {
        path = '/t/',
        method = 'GET'
      },
      {
        path = '/u/',
        method = 'GET'
      },
      {
        path = '/v/',
        method = 'GET'
      },
      {
        path = '/w/',
        method = 'GET'
      },
      {
        path = '/x/',
        method = 'GET'
      },
      {
        path = '/y/',
        method = 'GET'
      },
      {
        path = '/z/',
        method = 'GET'
      },
      {
        path = '/acceso/',
        method = 'GET'
      },
      {
        path = '/access/',
        method = 'GET'
      },
      {
        path = '/accesswatch/',
        method = 'GET'
      },
      {
        path = '/acciones/',
        method = 'GET'
      },
      {
        path = '/account/',
        method = 'GET'
      },
      {
        path = '/accounting/',
        method = 'GET'
      },
      {
        path = '/active/',
        method = 'GET'
      },
      {
        path = '/activex/',
        method = 'GET'
      },
      {
        path = '/admcgi/',
        method = 'GET'
      },
      {
        path = '/admisapi/',
        method = 'GET'
      },
      {
        path = '/AdvWebAdmin/',
        method = 'GET'
      },
      {
        path = '/agentes/',
        method = 'GET'
      },
      {
        path = '/Agent/',
        method = 'GET'
      },
      {
        path = '/Agents/',
        method = 'GET'
      },
      {
        path = '/AlbumArt_/',
        method = 'GET'
      },
      {
        path = '/AlbumArt/',
        method = 'GET'
      },
      {
        path = '/Album/',
        method = 'GET'
      },
      {
        path = '/allow/',
        method = 'GET'
      },
      {
        path = '/analog/',
        method = 'GET'
      },
      {
        path = '/anthill/',
        method = 'GET'
      },
      {
        path = '/apache/',
        method = 'GET'
      },
      {
        path = '/app/',
        method = 'GET'
      },
      {
        path = '/applets/',
        method = 'GET'
      },
      {
        path = '/appl/',
        method = 'GET'
      },
      {
        path = '/application/',
        method = 'GET'
      },
      {
        path = '/applications/',
        method = 'GET'
      },
      {
        path = '/applmgr/',
        method = 'GET'
      },
      {
        path = '/apply/',
        method = 'GET'
      },
      {
        path = '/appsec/',
        method = 'GET'
      },
      {
        path = '/apps/',
        method = 'GET'
      },
      {
        path = '/archive/',
        method = 'GET'
      },
      {
        path = '/archives/',
        method = 'GET'
      },
      {
        path = '/ar/',
        method = 'GET'
      },
      {
        path = '/asa/',
        method = 'GET'
      },
      {
        path = '/asp/',
        method = 'GET'
      },
      {
        path = '/atc/',
        method = 'GET'
      },
      {
        path = '/aut/',
        method = 'GET'
      },
      {
        path = '/authadmin/',
        method = 'GET'
      },
      {
        path = '/auth/',
        method = 'GET'
      },
      {
        path = '/author/',
        method = 'GET'
      },
      {
        path = '/authors/',
        method = 'GET'
      },
      {
        path = '/aw/',
        method = 'GET'
      },
      {
        path = '/ayuda/',
        method = 'GET'
      },
      {
        path = '/b2-include/',
        method = 'GET'
      },
      {
        path = '/backend/',
        method = 'GET'
      },
      {
        path = '/bad/',
        method = 'GET'
      },
      {
        path = '/banca/',
        method = 'GET'
      },
      {
        path = '/banco/',
        method = 'GET'
      },
      {
        path = '/bank/',
        method = 'GET'
      },
      {
        path = '/banner01/',
        method = 'GET'
      },
      {
        path = '/banner/',
        method = 'GET'
      },
      {
        path = '/banners/',
        method = 'GET'
      },
      {
        path = '/bar/',
        method = 'GET'
      },
      {
        path = '/batch/',
        method = 'GET'
      },
      {
        path = '/bb-dnbd/',
        method = 'GET'
      },
      {
        path = '/bbv/',
        method = 'GET'
      },
      {
        path = '/bdata/',
        method = 'GET'
      },
      {
        path = '/bdatos/',
        method = 'GET'
      },
      {
        path = '/beta/',
        method = 'GET'
      },
      {
        path = '/billpay/',
        method = 'GET'
      },
      {
        path = '/bin/',
        method = 'GET'
      },
      {
        path = '/binaries/',
        method = 'GET'
      },
      {
        path = '/binary/',
        method = 'GET'
      },
      {
        path = '/boadmin/',
        method = 'GET'
      },
      {
        path = '/boot/',
        method = 'GET'
      },
      {
        path = '/bottom/',
        method = 'GET'
      },
      {
        path = '/browse/',
        method = 'GET'
      },
      {
        path = '/browser/',
        method = 'GET'
      },
      {
        path = '/bsd/',
        method = 'GET'
      },
      {
        path = '/btauxdir/',
        method = 'GET'
      },
      {
        path = '/bug/',
        method = 'GET'
      },
      {
        path = '/bugs/',
        method = 'GET'
      },
      {
        path = '/bugzilla/',
        method = 'GET'
      },
      {
        path = '/buy/',
        method = 'GET'
      },
      {
        path = '/buynow/',
        method = 'GET'
      },
      {
        path = '/cached/',
        method = 'GET'
      },
      {
        path = '/cache/',
        method = 'GET'
      },
      {
        path = '/cache-stats/',
        method = 'GET'
      },
      {
        path = '/caja/',
        method = 'GET'
      },
      {
        path = '/card/',
        method = 'GET'
      },
      {
        path = '/cards/',
        method = 'GET'
      },
      {
        path = '/cart/',
        method = 'GET'
      },
      {
        path = '/cash/',
        method = 'GET'
      },
      {
        path = '/caspsamp/',
        method = 'GET'
      },
      {
        path = '/catalog/',
        method = 'GET'
      },
      {
        path = '/cbi-bin/',
        method = 'GET'
      },
      {
        path = '/ccard/',
        method = 'GET'
      },
      {
        path = '/ccards/',
        method = 'GET'
      },
      {
        path = '/cd-cgi/',
        method = 'GET'
      },
      {
        path = '/cd/',
        method = 'GET'
      },
      {
        path = '/cdrom/',
        method = 'GET'
      },
      {
        path = '/ce_html/',
        method = 'GET'
      },
      {
        path = '/cert/',
        method = 'GET'
      },
      {
        path = '/certificado/',
        method = 'GET'
      },
      {
        path = '/certificate/',
        method = 'GET'
      },
      {
        path = '/cfappman/',
        method = 'GET'
      },
      {
        path = '/cfdocs/',
        method = 'GET'
      },
      {
        path = '/cfide/',
        method = 'GET'
      },
      {
        path = '/cgi-914/',
        method = 'GET'
      },
      {
        path = '/cgi-915/',
        method = 'GET'
      },
      {
        path = '/cgi-auth/',
        method = 'GET'
      },
      {
        path = '/cgi-bin2/',
        method = 'GET'
      },
      {
        path = '/cgi-bin/',
        method = 'GET'
      },
      {
        path = '/cgibin/',
        method = 'GET'
      },
      {
        path = '/cgi.cgi/',
        method = 'GET'
      },
      {
        path = '/cgi-csc/',
        method = 'GET'
      },
      {
        path = '/cgi-exe/',
        method = 'GET'
      },
      {
        path = '/cgi/',
        method = 'GET'
      },
      {
        path = '/cgi-home/',
        method = 'GET'
      },
      {
        path = '/cgi-lib/',
        method = 'GET'
      },
      {
        path = '/cgilib/',
        method = 'GET'
      },
      {
        path = '/cgi-local/',
        method = 'GET'
      },
      {
        path = '/cgi-perl/',
        method = 'GET'
      },
      {
        path = '/cgi-scripts/',
        method = 'GET'
      },
      {
        path = '/cgiscripts/',
        method = 'GET'
      },
      {
        path = '/cgis/',
        method = 'GET'
      },
      {
        path = '/cgi-shl/',
        method = 'GET'
      },
      {
        path = '/cgi-shop/',
        method = 'GET'
      },
      {
        path = '/cgi-sys/',
        method = 'GET'
      },
      {
        path = '/cgi-weddico/',
        method = 'GET'
      },
      {
        path = '/cgi-win/',
        method = 'GET'
      },
      {
        path = '/cgiwin/',
        method = 'GET'
      },
      {
        path = '/class/',
        method = 'GET'
      },
      {
        path = '/classes/',
        method = 'GET'
      },
      {
        path = '/cliente/',
        method = 'GET'
      },
      {
        path = '/clientes/',
        method = 'GET'
      },
      {
        path = '/client/',
        method = 'GET'
      },
      {
        path = '/clients/',
        method = 'GET'
      },
      {
        path = '/cm/',
        method = 'GET'
      },
      {
        path = '/cobalt-images/',
        method = 'GET'
      },
      {
        path = '/code/',
        method = 'GET'
      },
      {
        path = '/com/',
        method = 'GET'
      },
      {
        path = '/comments/',
        method = 'GET'
      },
      {
        path = '/common/',
        method = 'GET'
      },
      {
        path = '/communicator/',
        method = 'GET'
      },
      {
        path = '/company/',
        method = 'GET'
      },
      {
        path = '/comp/',
        method = 'GET'
      },
      {
        path = '/compra/',
        method = 'GET'
      },
      {
        path = '/compras/',
        method = 'GET'
      },
      {
        path = '/compressed/',
        method = 'GET'
      },
      {
        path = '/conecta/',
        method = 'GET'
      },
      {
        path = '/conf/',
        method = 'GET'
      },
      {
        path = '/config/',
        method = 'GET'
      },
      {
        path = '/configs/',
        method = 'GET'
      },
      {
        path = '/configure/',
        method = 'GET'
      },
      {
        path = '/connect/',
        method = 'GET'
      },
      {
        path = '/console/',
        method = 'GET'
      },
      {
        path = '/contact/',
        method = 'GET'
      },
      {
        path = '/contacts/',
        method = 'GET'
      },
      {
        path = '/content/',
        method = 'GET'
      },
      {
        path = '/content.ie5/',
        method = 'GET'
      },
      {
        path = '/controlpanel/',
        method = 'GET'
      },
      {
        path = '/core/',
        method = 'GET'
      },
      {
        path = '/corp/',
        method = 'GET'
      },
      {
        path = '/correo/',
        method = 'GET'
      },
      {
        path = '/counter/',
        method = 'GET'
      },
      {
        path = '/credit/',
        method = 'GET'
      },
      {
        path = '/cron/',
        method = 'GET'
      },
      {
        path = '/crons/',
        method = 'GET'
      },
      {
        path = '/crypto/',
        method = 'GET'
      },
      {
        path = '/CS/',
        method = 'GET'
      },
      {
        path = '/csr/',
        method = 'GET'
      },
      {
        path = '/css/',
        method = 'GET'
      },
      {
        path = '/cuenta/',
        method = 'GET'
      },
      {
        path = '/cuentas/',
        method = 'GET'
      },
      {
        path = '/currency/',
        method = 'GET'
      },
      {
        path = '/cust/',
        method = 'GET'
      },
      {
        path = '/customer/',
        method = 'GET'
      },
      {
        path = '/customers/',
        method = 'GET'
      },
      {
        path = '/custom/',
        method = 'GET'
      },
      {
        path = '/CVS/',
        method = 'GET'
      },
      {
        path = '/cvsweb/',
        method = 'GET'
      },
      {
        path = '/cybercash/',
        method = 'GET'
      },
      {
        path = '/darkportal/',
        method = 'GET'
      },
      {
        path = '/database/',
        method = 'GET'
      },
      {
        path = '/databases/',
        method = 'GET'
      },
      {
        path = '/datafiles/',
        method = 'GET'
      },
      {
        path = '/dat/',
        method = 'GET'
      },
      {
        path = '/data/',
        method = 'GET'
      },
      {
        path = '/dato/',
        method = 'GET'
      },
      {
        path = '/datos/',
        method = 'GET'
      },
      {
        path = '/db/',
        method = 'GET'
      },
      {
        path = '/dbase/',
        method = 'GET'
      },
      {
        path = '/dcforum/',
        method = 'GET'
      },
      {
        path = '/ddreport/',
        method = 'GET'
      },
      {
        path = '/ddrint/',
        method = 'GET'
      },
      {
        path = '/debug/',
        method = 'GET'
      },
      {
        path = '/debugs/',
        method = 'GET'
      },
      {
        path = '/default/',
        method = 'GET'
      },
      {
        path = '/deleted/',
        method = 'GET'
      },
      {
        path = '/delete/',
        method = 'GET'
      },
      {
        path = '/demoauct/',
        method = 'GET'
      },
      {
        path = '/demomall/',
        method = 'GET'
      },
      {
        path = '/demo/',
        method = 'GET'
      },
      {
        path = '/demos/',
        method = 'GET'
      },
      {
        path = '/demouser/',
        method = 'GET'
      },
      {
        path = '/deny/',
        method = 'GET'
      },
      {
        path = '/derived/',
        method = 'GET'
      },
      {
        path = '/design/',
        method = 'GET'
      },
      {
        path = '/dev/',
        method = 'GET'
      },
      {
        path = '/devel/',
        method = 'GET'
      },
      {
        path = '/development/',
        method = 'GET'
      },
      {
        path = '/directories/',
        method = 'GET'
      },
      {
        path = '/directory/',
        method = 'GET'
      },
      {
        path = '/directorymanager/',
        method = 'GET'
      },
      {
        path = '/dir/',
        method = 'GET'
      },
      {
        path = '/dl/',
        method = 'GET'
      },
      {
        path = '/dm/',
        method = 'GET'
      },
      {
        path = '/DMR/',
        method = 'GET'
      },
      {
        path = '/dms0/',
        method = 'GET'
      },
      {
        path = '/dmsdump/',
        method = 'GET'
      },
      {
        path = '/dms/',
        method = 'GET'
      },
      {
        path = '/dnn/',
        method = 'GET'
      },
      {
        path = '/doc1/',
        method = 'GET'
      },
      {
        path = '/doc/',
        method = 'GET'
      },
      {
        path = '/doc-html/',
        method = 'GET'
      },
      {
        path = '/docs1/',
        method = 'GET'
      },
      {
        path = '/docs/',
        method = 'GET'
      },
      {
        path = '/DocuColor/',
        method = 'GET'
      },
      {
        path = '/documentation/',
        method = 'GET'
      },
      {
        path = '/document/',
        method = 'GET'
      },
      {
        path = '/documents/',
        method = 'GET'
      },
      {
        path = '/dotnetnuke/',
        method = 'GET'
      },
      {
        path = '/down/',
        method = 'GET'
      },
      {
        path = '/download/',
        method = 'GET'
      },
      {
        path = '/downloads/',
        method = 'GET'
      },
      {
        path = '/dump/',
        method = 'GET'
      },
      {
        path = '/durep/',
        method = 'GET'
      },
      {
        path = '/easylog/',
        method = 'GET'
      },
      {
        path = '/eforum/',
        method = 'GET'
      },
      {
        path = '/ejemplo/',
        method = 'GET'
      },
      {
        path = '/ejemplos/',
        method = 'GET'
      },
      {
        path = '/emailclass/',
        method = 'GET'
      },
      {
        path = '/email/',
        method = 'GET'
      },
      {
        path = '/employees/',
        method = 'GET'
      },
      {
        path = '/empoyees/',
        method = 'GET'
      },
      {
        path = '/empris/',
        method = 'GET'
      },
      {
        path = '/enter/',
        method = 'GET'
      },
      {
        path = '/envia/',
        method = 'GET'
      },
      {
        path = '/enviamail/',
        method = 'GET'
      },
      {
        path = '/error/',
        method = 'GET'
      },
      {
        path = '/errors/',
        method = 'GET'
      },
      {
        path = '/es/',
        method = 'GET'
      },
      {
        path = '/estmt/',
        method = 'GET'
      },
      {
        path = '/etc/',
        method = 'GET'
      },
      {
        path = '/etcpasswd/',
        method = 'GET'
      },
      {
        path = '/excel/',
        method = 'GET'
      },
      {
        path = '/exc/',
        method = 'GET'
      },
      {
        path = '/exchange/',
        method = 'GET'
      },
      {
        path = '/exchweb/',
        method = 'GET'
      },
      {
        path = '/exec/',
        method = 'GET'
      },
      {
        path = '/exe/',
        method = 'GET'
      },
      {
        path = '/exit/',
        method = 'GET'
      },
      {
        path = '/export/',
        method = 'GET'
      },
      {
        path = '/external/',
        method = 'GET'
      },
      {
        path = '/extranet/',
        method = 'GET'
      },
      {
        path = '/failure/',
        method = 'GET'
      },
      {
        path = '/fbsd/',
        method = 'GET'
      },
      {
        path = '/fcgi-bin/',
        method = 'GET'
      },
      {
        path = '/fcgi/',
        method = 'GET'
      },
      {
        path = '/features/',
        method = 'GET'
      },
      {
        path = '/fileadmin/',
        method = 'GET'
      },
      {
        path = '/file/',
        method = 'GET'
      },
      {
        path = '/filemanager/',
        method = 'GET'
      },
      {
        path = '/files/',
        method = 'GET'
      },
      {
        path = '/find/',
        method = 'GET'
      },
      {
        path = '/flash/',
        method = 'GET'
      },
      {
        path = '/foldoc/',
        method = 'GET'
      },
      {
        path = '/foobar/',
        method = 'GET'
      },
      {
        path = '/foo/',
        method = 'GET'
      },
      {
        path = '/form/',
        method = 'GET'
      },
      {
        path = '/forms/',
        method = 'GET'
      },
      {
        path = '/formsmgr/',
        method = 'GET'
      },
      {
        path = '/form-totaller/',
        method = 'GET'
      },
      {
        path = '/foto/',
        method = 'GET'
      },
      {
        path = '/fotos/',
        method = 'GET'
      },
      {
        path = '/fpadmin/',
        method = 'GET'
      },
      {
        path = '/fpclass/',
        method = 'GET'
      },
      {
        path = '/fpdb/',
        method = 'GET'
      },
      {
        path = '/fpe/',
        method = 'GET'
      },
      {
        path = '/framesets/',
        method = 'GET'
      },
      {
        path = '/frames/',
        method = 'GET'
      },
      {
        path = '/frontpage/',
        method = 'GET'
      },
      {
        path = '/ftp/',
        method = 'GET'
      },
      {
        path = '/ftproot/',
        method = 'GET'
      },
      {
        path = '/func/',
        method = 'GET'
      },
      {
        path = '/function/',
        method = 'GET'
      },
      {
        path = '/functions/',
        method = 'GET'
      },
      {
        path = '/fun/',
        method = 'GET'
      },
      {
        path = '/general/',
        method = 'GET'
      },
      {
        path = '/gfx/',
        method = 'GET'
      },
      {
        path = '/gif/',
        method = 'GET'
      },
      {
        path = '/gifs/',
        method = 'GET'
      },
      {
        path = '/global/',
        method = 'GET'
      },
      {
        path = '/globals/',
        method = 'GET'
      },
      {
        path = '/good/',
        method = 'GET'
      },
      {
        path = '/graphics/',
        method = 'GET'
      },
      {
        path = '/grocery/',
        method = 'GET'
      },
      {
        path = '/guestbook/',
        method = 'GET'
      },
      {
        path = '/guest/',
        method = 'GET'
      },
      {
        path = '/guests/',
        method = 'GET'
      },
      {
        path = '/GXApp/',
        method = 'GET'
      },
      {
        path = '/HB/',
        method = 'GET'
      },
      {
        path = '/HBTemplates/',
        method = 'GET'
      },
      {
        path = '/helpdesk/',
        method = 'GET'
      },
      {
        path = '/help/',
        method = 'GET'
      },
      {
        path = '/hidden/',
        method = 'GET'
      },
      {
        path = '/hide/',
        method = 'GET'
      },
      {
        path = '/hitmatic/',
        method = 'GET'
      },
      {
        path = '/hit_tracker/',
        method = 'GET'
      },
      {
        path = '/hlstats/',
        method = 'GET'
      },
      {
        path = '/home/',
        method = 'GET'
      },
      {
        path = '/hosted/',
        method = 'GET'
      },
      {
        path = '/host/',
        method = 'GET'
      },
      {
        path = '/hostingcontroller/',
        method = 'GET'
      },
      {
        path = '/hosting/',
        method = 'GET'
      },
      {
        path = '/hp/',
        method = 'GET'
      },
      {
        path = '/htbin/',
        method = 'GET'
      },
      {
        path = '/htdocs/',
        method = 'GET'
      },
      {
        path = '/ht/',
        method = 'GET'
      },
      {
        path = '/htm/',
        method = 'GET'
      },
      {
        path = '/html/',
        method = 'GET'
      },
      {
        path = '/http/',
        method = 'GET'
      },
      {
        path = '/https/',
        method = 'GET'
      },
      {
        path = '/hyperstat/',
        method = 'GET'
      },
      {
        path = '/i18n/',
        method = 'GET'
      },
      {
        path = '/ibank/',
        method = 'GET'
      },
      {
        path = '/ibill/',
        method = 'GET'
      },
      {
        path = '/IBMWebAS/',
        method = 'GET'
      },
      {
        path = '/icons/',
        method = 'GET'
      },
      {
        path = '/idea/',
        method = 'GET'
      },
      {
        path = '/ideas/',
        method = 'GET'
      },
      {
        path = '/I/',
        method = 'GET'
      },
      {
        path = '/iisadmin/',
        method = 'GET'
      },
      {
        path = '/image/',
        method = 'GET'
      },
      {
        path = '/images/',
        method = 'GET'
      },
      {
        path = '/imagenes/',
        method = 'GET'
      },
      {
        path = '/imagery/',
        method = 'GET'
      },
      {
        path = '/img/',
        method = 'GET'
      },
      {
        path = '/imp/',
        method = 'GET'
      },
      {
        path = '/import/',
        method = 'GET'
      },
      {
        path = '/impreso/',
        method = 'GET'
      },
      {
        path = '/inc/',
        method = 'GET'
      },
      {
        path = '/include/',
        method = 'GET'
      },
      {
        path = '/includes/',
        method = 'GET'
      },
      {
        path = '/incoming/',
        method = 'GET'
      },
      {
        path = '/index/',
        method = 'GET'
      },
      {
        path = '/inet/',
        method = 'GET'
      },
      {
        path = '/inf/',
        method = 'GET'
      },
      {
        path = '/info/',
        method = 'GET'
      },
      {
        path = '/information/',
        method = 'GET'
      },
      {
        path = '/in/',
        method = 'GET'
      },
      {
        path = '/ingresa/',
        method = 'GET'
      },
      {
        path = '/ingreso/',
        method = 'GET'
      },
      {
        path = '/install/',
        method = 'GET'
      },
      {
        path = '/internal/',
        method = 'GET'
      },
      {
        path = '/internet/',
        method = 'GET'
      },
      {
        path = '/intranet/',
        method = 'GET'
      },
      {
        path = '/inventory/',
        method = 'GET'
      },
      {
        path = '/invitado/',
        method = 'GET'
      },
      {
        path = '/isapi/',
        method = 'GET'
      },
      {
        path = '/j2ee/',
        method = 'GET'
      },
      {
        path = '/japidoc/',
        method = 'GET'
      },
      {
        path = '/java/',
        method = 'GET'
      },
      {
        path = '/javascript/',
        method = 'GET'
      },
      {
        path = '/javasdk/',
        method = 'GET'
      },
      {
        path = '/javatest/',
        method = 'GET'
      },
      {
        path = '/jave/',
        method = 'GET'
      },
      {
        path = '/JBookIt/',
        method = 'GET'
      },
      {
        path = '/jdbc/',
        method = 'GET'
      },
      {
        path = '/job/',
        method = 'GET'
      },
      {
        path = '/jrun/',
        method = 'GET'
      },
      {
        path = '/jsa/',
        method = 'GET'
      },
      {
        path = '/jscript/',
        method = 'GET'
      },
      {
        path = '/jserv/',
        method = 'GET'
      },
      {
        path = '/js/',
        method = 'GET'
      },
      {
        path = '/jslib/',
        method = 'GET'
      },
      {
        path = '/jsp/',
        method = 'GET'
      },
      {
        path = '/junk/',
        method = 'GET'
      },
      {
        path = '/kiva/',
        method = 'GET'
      },
      {
        path = '/known/',
        method = 'GET'
      },
      {
        path = '/labs/',
        method = 'GET'
      },
      {
        path = '/lcgi/',
        method = 'GET'
      },
      {
        path = '/lib/',
        method = 'GET'
      },
      {
        path = '/libraries/',
        method = 'GET'
      },
      {
        path = '/library/',
        method = 'GET'
      },
      {
        path = '/libro/',
        method = 'GET'
      },
      {
        path = '/license/',
        method = 'GET'
      },
      {
        path = '/licenses/',
        method = 'GET'
      },
      {
        path = '/links/',
        method = 'GET'
      },
      {
        path = '/linux/',
        method = 'GET'
      },
      {
        path = '/loader/',
        method = 'GET'
      },
      {
        path = '/local/',
        method = 'GET'
      },
      {
        path = '/location/',
        method = 'GET'
      },
      {
        path = '/locations/',
        method = 'GET'
      },
      {
        path = '/logfile/',
        method = 'GET'
      },
      {
        path = '/logfiles/',
        method = 'GET'
      },
      {
        path = '/logger/',
        method = 'GET'
      },
      {
        path = '/logg/',
        method = 'GET'
      },
      {
        path = '/logging/',
        method = 'GET'
      },
      {
        path = '/logon/',
        method = 'GET'
      },
      {
        path = '/logout/',
        method = 'GET'
      },
      {
        path = '/lost+found/',
        method = 'GET'
      },
      {
        path = '/mailman/',
        method = 'GET'
      },
      {
        path = '/mailroot/',
        method = 'GET'
      },
      {
        path = '/makefile/',
        method = 'GET'
      },
      {
        path = '/manage/',
        method = 'GET'
      },
      {
        path = '/management/',
        method = 'GET'
      },
      {
        path = '/man/',
        method = 'GET'
      },
      {
        path = '/manual/',
        method = 'GET'
      },
      {
        path = '/map/',
        method = 'GET'
      },
      {
        path = '/maps/',
        method = 'GET'
      },
      {
        path = '/marketing/',
        method = 'GET'
      },
      {
        path = '/member/',
        method = 'GET'
      },
      {
        path = '/members/',
        method = 'GET'
      },
      {
        path = '/mem_bin/',
        method = 'GET'
      },
      {
        path = '/mem/',
        method = 'GET'
      },
      {
        path = '/message/',
        method = 'GET'
      },
      {
        path = '/messaging/',
        method = 'GET'
      },
      {
        path = '/metacart/',
        method = 'GET'
      },
      {
        path = '/microsoft/',
        method = 'GET'
      },
      {
        path = '/misc/',
        method = 'GET'
      },
      {
        path = '/mkstats/',
        method = 'GET'
      },
      {
        path = '/mod/',
        method = 'GET'
      },
      {
        path = '/module/',
        method = 'GET'
      },
      {
        path = '/modules/',
        method = 'GET'
      },
      {
        path = '/movimientos/',
        method = 'GET'
      },
      {
        path = '/mpcgi/',
        method = 'GET'
      },
      {
        path = '/mqseries/',
        method = 'GET'
      },
      {
        path = '/msfpe/',
        method = 'GET'
      },
      {
        path = '/ms/',
        method = 'GET'
      },
      {
        path = '/msql/',
        method = 'GET'
      },
      {
        path = '/Msword/',
        method = 'GET'
      },
      {
        path = '/mxhtml/',
        method = 'GET'
      },
      {
        path = '/mxportal/',
        method = 'GET'
      },
      {
        path = '/my/',
        method = 'GET'
      },
      {
        path = '/My%20Shared%20Folder/',
        method = 'GET'
      },
      {
        path = '/mysql_admin/',
        method = 'GET'
      },
      {
        path = '/mysql/',
        method = 'GET'
      },
      {
        path = '/name/',
        method = 'GET'
      },
      {
        path = '/names/',
        method = 'GET'
      },
      {
        path = '/ncadmin/',
        method = 'GET'
      },
      {
        path = '/nchelp/',
        method = 'GET'
      },
      {
        path = '/netbasic/',
        method = 'GET'
      },
      {
        path = '/netcat/',
        method = 'GET'
      },
      {
        path = '/NetDynamic/',
        method = 'GET'
      },
      {
        path = '/NetDynamics/',
        method = 'GET'
      },
      {
        path = '/net/',
        method = 'GET'
      },
      {
        path = '/netmagstats/',
        method = 'GET'
      },
      {
        path = '/netscape/',
        method = 'GET'
      },
      {
        path = '/netshare/',
        method = 'GET'
      },
      {
        path = '/nettracker/',
        method = 'GET'
      },
      {
        path = '/network/',
        method = 'GET'
      },
      {
        path = '/new/',
        method = 'GET'
      },
      {
        path = '/news/',
        method = 'GET'
      },
      {
        path = '/News/',
        method = 'GET'
      },
      {
        path = '/nextgeneration/',
        method = 'GET'
      },
      {
        path = '/nl/',
        method = 'GET'
      },
      {
        path = '/notes/',
        method = 'GET'
      },
      {
        path = '/noticias/',
        method = 'GET'
      },
      {
        path = '/NSearch/',
        method = 'GET'
      },
      {
        path = '/objects/',
        method = 'GET'
      },
      {
        path = '/odbc/',
        method = 'GET'
      },
      {
        path = '/officescan/',
        method = 'GET'
      },
      {
        path = '/ojspdemos/',
        method = 'GET'
      },
      {
        path = '/old_files/',
        method = 'GET'
      },
      {
        path = '/oldfiles/',
        method = 'GET'
      },
      {
        path = '/old/',
        method = 'GET'
      },
      {
        path = '/oprocmgr-service/',
        method = 'GET'
      },
      {
        path = '/oprocmgr-status/',
        method = 'GET'
      },
      {
        path = '/oracle/',
        method = 'GET'
      },
      {
        path = '/oradata/',
        method = 'GET'
      },
      {
        path = '/order/',
        method = 'GET'
      },
      {
        path = '/orders/',
        method = 'GET'
      },
      {
        path = '/os/',
        method = 'GET'
      },
      {
        path = '/out/',
        method = 'GET'
      },
      {
        path = '/outgoing/',
        method = 'GET'
      },
      {
        path = '/owners/',
        method = 'GET'
      },
      {
        path = '/ows-bin/',
        method = 'GET'
      },
      {
        path = '/page/',
        method = 'GET'
      },
      {
        path = '/_pages/',
        method = 'GET'
      },
      {
        path = '/pages/',
        method = 'GET'
      },
      {
        path = '/partner/',
        method = 'GET'
      },
      {
        path = '/partners/',
        method = 'GET'
      },
      {
        path = '/passport/',
        method = 'GET'
      },
      {
        path = '/password/',
        method = 'GET'
      },
      {
        path = '/passwords/',
        method = 'GET'
      },
      {
        path = '/path/',
        method = 'GET'
      },
      {
        path = '/payment/',
        method = 'GET'
      },
      {
        path = '/payments/',
        method = 'GET'
      },
      {
        path = '/pccsmysqladm/',
        method = 'GET'
      },
      {
        path = '/PDG_Cart/',
        method = 'GET'
      },
      {
        path = '/perl5/',
        method = 'GET'
      },
      {
        path = '/perl/',
        method = 'GET'
      },
      {
        path = '/personal/',
        method = 'GET'
      },
      {
        path = '/pforum/',
        method = 'GET'
      },
      {
        path = '/phorum/',
        method = 'GET'
      },
      {
        path = '/phpBB/',
        method = 'GET'
      },
      {
        path = '/php_classes/',
        method = 'GET'
      },
      {
        path = '/phpclassifieds/',
        method = 'GET'
      },
      {
        path = '/php/',
        method = 'GET'
      },
      {
        path = '/phpimageview/',
        method = 'GET'
      },
      {
        path = '/phpnuke/',
        method = 'GET'
      },
      {
        path = '/phpPhotoAlbum/',
        method = 'GET'
      },
      {
        path = '/phpprojekt/',
        method = 'GET'
      },
      {
        path = '/phpSecurePages/',
        method = 'GET'
      },
      {
        path = '/pics/',
        method = 'GET'
      },
      {
        path = '/pictures/',
        method = 'GET'
      },
      {
        path = '/pike/',
        method = 'GET'
      },
      {
        path = '/piranha/',
        method = 'GET'
      },
      {
        path = '/pls/',
        method = 'GET'
      },
      {
        path = '/plsql/',
        method = 'GET'
      },
      {
        path = '/plssampleadmin_/',
        method = 'GET'
      },
      {
        path = '/plssampleadmin/',
        method = 'GET'
      },
      {
        path = '/plssampleadmin_help/',
        method = 'GET'
      },
      {
        path = '/plssample/',
        method = 'GET'
      },
      {
        path = '/poll/',
        method = 'GET'
      },
      {
        path = '/polls/',
        method = 'GET'
      },
      {
        path = '/porn/',
        method = 'GET'
      },
      {
        path = '/portal/',
        method = 'GET'
      },
      {
        path = '/portals/',
        method = 'GET'
      },
      {
        path = '/postgres/',
        method = 'GET'
      },
      {
        path = '/postnuke/',
        method = 'GET'
      },
      {
        path = '/ppwb/',
        method = 'GET'
      },
      {
        path = '/printer/',
        method = 'GET'
      },
      {
        path = '/printers/',
        method = 'GET'
      },
      {
        path = '/privacy/',
        method = 'GET'
      },
      {
        path = '/privado/',
        method = 'GET'
      },
      {
        path = '/_private/',
        method = 'GET'
      },
      {
        path = '/private/',
        method = 'GET'
      },
      {
        path = '/priv/',
        method = 'GET'
      },
      {
        path = '/prod/',
        method = 'GET'
      },
      {
        path = '/projectserver/',
        method = 'GET'
      },
      {
        path = '/protected/',
        method = 'GET'
      },
      {
        path = '/proxy/',
        method = 'GET'
      },
      {
        path = '/prueba/',
        method = 'GET'
      },
      {
        path = '/pruebas/',
        method = 'GET'
      },
      {
        path = '/prv/',
        method = 'GET'
      },
      {
        path = '/pub/',
        method = 'GET'
      },
      {
        path = '/_public/',
        method = 'GET'
      },
      {
        path = '/public/',
        method = 'GET'
      },
      {
        path = '/publica/',
        method = 'GET'
      },
      {
        path = '/publicar/',
        method = 'GET'
      },
      {
        path = '/publico/',
        method = 'GET'
      },
      {
        path = '/publish/',
        method = 'GET'
      },
      {
        path = '/purchase/',
        method = 'GET'
      },
      {
        path = '/purchases/',
        method = 'GET'
      },
      {
        path = '/pw/',
        method = 'GET'
      },
      {
        path = '/python/',
        method = 'GET'
      },
      {
        path = '/random_banner/',
        method = 'GET'
      },
      {
        path = '/rdp/',
        method = 'GET'
      },
      {
        path = '/Readme/',
        method = 'GET'
      },
      {
        path = '/recycler/',
        method = 'GET'
      },
      {
        path = '/registered/',
        method = 'GET'
      },
      {
        path = '/register/',
        method = 'GET'
      },
      {
        path = '/registry/',
        method = 'GET'
      },
      {
        path = '/remote/',
        method = 'GET'
      },
      {
        path = '/remove/',
        method = 'GET'
      },
      {
        path = '/report/',
        method = 'GET'
      },
      {
        path = '/reports/',
        method = 'GET'
      },
      {
        path = '/reseller/',
        method = 'GET'
      },
      {
        path = '/restricted/',
        method = 'GET'
      },
      {
        path = '/retail/',
        method = 'GET'
      },
      {
        path = '/reveal/',
        method = 'GET'
      },
      {
        path = '/reviews/',
        method = 'GET'
      },
      {
        path = '/ROADS/',
        method = 'GET'
      },
      {
        path = '/robot/',
        method = 'GET'
      },
      {
        path = '/robots/',
        method = 'GET'
      },
      {
        path = '/root/',
        method = 'GET'
      },
      {
        path = '/rsrc/',
        method = 'GET'
      },
      {
        path = '/ruby/',
        method = 'GET'
      },
      {
        path = '/sales/',
        method = 'GET'
      },
      {
        path = '/save/',
        method = 'GET'
      },
      {
        path = '/script/',
        method = 'GET'
      },
      {
        path = '/ScriptLibrary/',
        method = 'GET'
      },
      {
        path = '/scripts/',
        method = 'GET'
      },
      {
        path = '/search/',
        method = 'GET'
      },
      {
        path = '/search-ui/',
        method = 'GET'
      },
      {
        path = '/sec/',
        method = 'GET'
      },
      {
        path = '/secret/',
        method = 'GET'
      },
      {
        path = '/secured/',
        method = 'GET'
      },
      {
        path = '/secure/',
        method = 'GET'
      },
      {
        path = '/security/',
        method = 'GET'
      },
      {
        path = '/sell/',
        method = 'GET'
      },
      {
        path = '/server/',
        method = 'GET'
      },
      {
        path = '/server-info/',
        method = 'GET'
      },
      {
        path = '/servers/',
        method = 'GET'
      },
      {
        path = '/server_stats/',
        method = 'GET'
      },
      {
        path = '/serverstats/',
        method = 'GET'
      },
      {
        path = '/server-status/',
        method = 'GET'
      },
      {
        path = '/service/',
        method = 'GET'
      },
      {
        path = '/services/',
        method = 'GET'
      },
      {
        path = '/servicio/',
        method = 'GET'
      },
      {
        path = '/servicios/',
        method = 'GET'
      },
      {
        path = '/servlet/',
        method = 'GET'
      },
      {
        path = '/servlets/',
        method = 'GET'
      },
      {
        path = '/session/',
        method = 'GET'
      },
      {
        path = '/setup/',
        method = 'GET'
      },
      {
        path = '/shared/',
        method = 'GET'
      },
      {
        path = '/sharedtemplates/',
        method = 'GET'
      },
      {
        path = '/share/',
        method = 'GET'
      },
      {
        path = '/shell-cgi/',
        method = 'GET'
      },
      {
        path = '/shipping/',
        method = 'GET'
      },
      {
        path = '/shop/',
        method = 'GET'
      },
      {
        path = '/shopper/',
        method = 'GET'
      },
      {
        path = '/show/',
        method = 'GET'
      },
      {
        path = '/SilverStream/',
        method = 'GET'
      },
      {
        path = '/siteadmin/',
        method = 'GET'
      },
      {
        path = '/site/',
        method = 'GET'
      },
      {
        path = '/sitemgr/',
        method = 'GET'
      },
      {
        path = '/siteminderagent/',
        method = 'GET'
      },
      {
        path = '/siteminder/',
        method = 'GET'
      },
      {
        path = '/siteserver/',
        method = 'GET'
      },
      {
        path = '/sites/',
        method = 'GET'
      },
      {
        path = '/sitestats/',
        method = 'GET'
      },
      {
        path = '/siteupdate/',
        method = 'GET'
      },
      {
        path = '/smreports/',
        method = 'GET'
      },
      {
        path = '/smreportsviewer/',
        method = 'GET'
      },
      {
        path = '/soapdocs/',
        method = 'GET'
      },
      {
        path = '/soap/',
        method = 'GET'
      },
      {
        path = '/software/',
        method = 'GET'
      },
      {
        path = '/solaris/',
        method = 'GET'
      },
      {
        path = '/source/',
        method = 'GET'
      },
      {
        path = '/sql/',
        method = 'GET'
      },
      {
        path = '/squid/',
        method = 'GET'
      },
      {
        path = '/src/',
        method = 'GET'
      },
      {
        path = '/srchadm/',
        method = 'GET'
      },
      {
        path = '/ssi/',
        method = 'GET'
      },
      {
        path = '/ssl/',
        method = 'GET'
      },
      {
        path = '/sslkeys/',
        method = 'GET'
      },
      {
        path = '/staff/',
        method = 'GET'
      },
      {
        path = '/state/',
        method = 'GET'
      },
      {
        path = '/stat/',
        method = 'GET'
      },
      {
        path = '/statistic/',
        method = 'GET'
      },
      {
        path = '/statistics/',
        method = 'GET'
      },
      {
        path = '/stats-bin-p/',
        method = 'GET'
      },
      {
        path = '/stats/',
        method = 'GET'
      },
      {
        path = '/stats_old/',
        method = 'GET'
      },
      {
        path = '/status/',
        method = 'GET'
      },
      {
        path = '/storage/',
        method = 'GET'
      },
      {
        path = '/StoreDB/',
        method = 'GET'
      },
      {
        path = '/store/',
        method = 'GET'
      },
      {
        path = '/storemgr/',
        method = 'GET'
      },
      {
        path = '/stronghold-info/',
        method = 'GET'
      },
      {
        path = '/stronghold-status/',
        method = 'GET'
      },
      {
        path = '/stuff/',
        method = 'GET'
      },
      {
        path = '/style/',
        method = 'GET'
      },
      {
        path = '/styles/',
        method = 'GET'
      },
      {
        path = '/stylesheet/',
        method = 'GET'
      },
      {
        path = '/stylesheets/',
        method = 'GET'
      },
      {
        path = '/subir/',
        method = 'GET'
      },
      {
        path = '/sun/',
        method = 'GET'
      },
      {
        path = '/super_stats/',
        method = 'GET'
      },
      {
        path = '/supplier/',
        method = 'GET'
      },
      {
        path = '/suppliers/',
        method = 'GET'
      },
      {
        path = '/supply/',
        method = 'GET'
      },
      {
        path = '/supporter/',
        method = 'GET'
      },
      {
        path = '/support/',
        method = 'GET'
      },
      {
        path = '/sysadmin/',
        method = 'GET'
      },
      {
        path = '/sysbackup/',
        method = 'GET'
      },
      {
        path = '/sys/',
        method = 'GET'
      },
      {
        path = '/system/',
        method = 'GET'
      },
      {
        path = '/systems/',
        method = 'GET'
      },
      {
        path = '/tar/',
        method = 'GET'
      },
      {
        path = '/target/',
        method = 'GET'
      },
      {
        path = '/tarjetas/',
        method = 'GET'
      },
      {
        path = '/tech/',
        method = 'GET'
      },
      {
        path = '/technote/',
        method = 'GET'
      },
      {
        path = '/te_html/',
        method = 'GET'
      },
      {
        path = '/temp/',
        method = 'GET'
      },
      {
        path = '/template/',
        method = 'GET'
      },
      {
        path = '/templates/',
        method = 'GET'
      },
      {
        path = '/temporal/',
        method = 'GET'
      },
      {
        path = '/test-cgi/',
        method = 'GET'
      },
      {
        path = '/testing/',
        method = 'GET'
      },
      {
        path = '/tests/',
        method = 'GET'
      },
      {
        path = '/testweb/',
        method = 'GET'
      },
      {
        path = '/themes/',
        method = 'GET'
      },
      {
        path = '/ticket/',
        method = 'GET'
      },
      {
        path = '/tickets/',
        method = 'GET'
      },
      {
        path = '/tip/',
        method = 'GET'
      },
      {
        path = '/tips/',
        method = 'GET'
      },
      {
        path = '/tmp/',
        method = 'GET'
      },
      {
        path = '/ToDo/',
        method = 'GET'
      },
      {
        path = '/tool/',
        method = 'GET'
      },
      {
        path = '/tools/',
        method = 'GET'
      },
      {
        path = '/TopAccess/',
        method = 'GET'
      },
      {
        path = '/top/',
        method = 'GET'
      },
      {
        path = '/tpv/',
        method = 'GET'
      },
      {
        path = '/trabajo/',
        method = 'GET'
      },
      {
        path = '/track/',
        method = 'GET'
      },
      {
        path = '/tracking/',
        method = 'GET'
      },
      {
        path = '/transfer/',
        method = 'GET'
      },
      {
        path = '/transito/',
        method = 'GET'
      },
      {
        path = '/transpolar/',
        method = 'GET'
      },
      {
        path = '/tree/',
        method = 'GET'
      },
      {
        path = '/trees/',
        method = 'GET'
      },
      {
        path = '/trick/',
        method = 'GET'
      },
      {
        path = '/tricks/',
        method = 'GET'
      },
      {
        path = '/u02/',
        method = 'GET'
      },
      {
        path = '/unix/',
        method = 'GET'
      },
      {
        path = '/unknown/',
        method = 'GET'
      },
      {
        path = '/updates/',
        method = 'GET'
      },
      {
        path = '/upload/',
        method = 'GET'
      },
      {
        path = '/uploads/',
        method = 'GET'
      },
      {
        path = '/usage/',
        method = 'GET'
      },
      {
        path = '/userdb/',
        method = 'GET'
      },
      {
        path = '/user/',
        method = 'GET'
      },
      {
        path = '/users/',
        method = 'GET'
      },
      {
        path = '/us/',
        method = 'GET'
      },
      {
        path = '/usr/',
        method = 'GET'
      },
      {
        path = '/ustats/',
        method = 'GET'
      },
      {
        path = '/usuario/',
        method = 'GET'
      },
      {
        path = '/usuarios/',
        method = 'GET'
      },
      {
        path = '/util/',
        method = 'GET'
      },
      {
        path = '/utils/',
        method = 'GET'
      },
      {
        path = '/vendor/',
        method = 'GET'
      },
      {
        path = '/vfs/',
        method = 'GET'
      },
      {
        path = '/view/',
        method = 'GET'
      },
      {
        path = '/vpn/',
        method = 'GET'
      },
      {
        path = '/vti_txt/',
        method = 'GET'
      },
      {
        path = '/w2000/',
        method = 'GET'
      },
      {
        path = '/w2k/',
        method = 'GET'
      },
      {
        path = '/w3perl/',
        method = 'GET'
      },
      {
        path = '/w-agora/',
        method = 'GET'
      },
      {
        path = '/way-board/',
        method = 'GET'
      },
      {
        path = '/web800fo/',
        method = 'GET'
      },
      {
        path = '/webaccess/',
        method = 'GET'
      },
      {
        path = '/webadmin/',
        method = 'GET'
      },
      {
        path = '/webAdmin/',
        method = 'GET'
      },
      {
        path = '/webalizer/',
        method = 'GET'
      },
      {
        path = '/webapps/',
        method = 'GET'
      },
      {
        path = '/WebBank/',
        method = 'GET'
      },
      {
        path = '/webboard/',
        method = 'GET'
      },
      {
        path = '/WebCalendar/',
        method = 'GET'
      },
      {
        path = '/webcart/',
        method = 'GET'
      },
      {
        path = '/webcart-lite/',
        method = 'GET'
      },
      {
        path = '/webcgi/',
        method = 'GET'
      },
      {
        path = '/webdata/',
        method = 'GET'
      },
      {
        path = '/webdav/',
        method = 'GET'
      },
      {
        path = '/webdb/',
        method = 'GET'
      },
      {
        path = '/webDB/',
        method = 'GET'
      },
      {
        path = '/web/',
        method = 'GET'
      },
      {
        path = '/webimages2/',
        method = 'GET'
      },
      {
        path = '/webimages/',
        method = 'GET'
      },
      {
        path = '/web-inf/',
        method = 'GET'
      },
      {
        path = '/webmaster/',
        method = 'GET'
      },
      {
        path = '/webmaster_logs/',
        method = 'GET'
      },
      {
        path = '/webMathematica/',
        method = 'GET'
      },
      {
        path = '/webpub/',
        method = 'GET'
      },
      {
        path = '/webpub-ui/',
        method = 'GET'
      },
      {
        path = '/webreports/',
        method = 'GET'
      },
      {
        path = '/webreps/',
        method = 'GET'
      },
      {
        path = '/webshare/',
        method = 'GET'
      },
      {
        path = '/WebShop/',
        method = 'GET'
      },
      {
        path = '/website/',
        method = 'GET'
      },
      {
        path = '/webstat/',
        method = 'GET'
      },
      {
        path = '/webstats/',
        method = 'GET'
      },
      {
        path = '/Web_store/',
        method = 'GET'
      },
      {
        path = '/webtrace/',
        method = 'GET'
      },
      {
        path = '/WebTrend/',
        method = 'GET'
      },
      {
        path = '/webtrends/',
        method = 'GET'
      },
      {
        path = '/web_usage/',
        method = 'GET'
      },
      {
        path = '/win2k/',
        method = 'GET'
      },
      {
        path = '/window/',
        method = 'GET'
      },
      {
        path = '/windows/',
        method = 'GET'
      },
      {
        path = '/win/',
        method = 'GET'
      },
      {
        path = '/winnt/',
        method = 'GET'
      },
      {
        path = '/word/',
        method = 'GET'
      },
      {
        path = '/work/',
        method = 'GET'
      },
      {
        path = '/world/',
        method = 'GET'
      },
      {
        path = '/wsdocs/',
        method = 'GET'
      },
      {
        path = '/WS_FTP/',
        method = 'GET'
      },
      {
        path = '/wstats/',
        method = 'GET'
      },
      {
        path = '/wusage/',
        method = 'GET'
      },
      {
        path = '/www0/',
        method = 'GET'
      },
      {
        path = '/www2/',
        method = 'GET'
      },
      {
        path = '/www3/',
        method = 'GET'
      },
      {
        path = '/www4/',
        method = 'GET'
      },
      {
        path = '/www/',
        method = 'GET'
      },
      {
        path = '/wwwjoin/',
        method = 'GET'
      },
      {
        path = '/wwwrooot/',
        method = 'GET'
      },
      {
        path = '/www-sql/',
        method = 'GET'
      },
      {
        path = '/wwwstat/',
        method = 'GET'
      },
      {
        path = '/wwwstats/',
        method = 'GET'
      },
      {
        path = '/xGB/',
        method = 'GET'
      },
      {
        path = '/xml/',
        method = 'GET'
      },
      {
        path = '/XSL/',
        method = 'GET'
      },
      {
        path = '/xtemp/',
        method = 'GET'
      },
      {
        path = '/xymon/',
        method = 'GET'
      },
      {
        path = '/zb41/',
        method = 'GET'
      },
      {
        path = '/zipfiles/',
        method = 'GET'
      },
      {
        path = '/zip/',
        method = 'GET'
      },
      {
        path = '/_docs/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of .*(Apache.*) Server at',
        output = 'Potentially interesting directory w/ listing on \'\\1\''
      },
      {
        match = '<title>Index of',
        output = 'Potentially interesting folder w/ directory listing'
      },
      {
        match = '',
        output = 'Potentially interesting folder'
      }
    }
  });

-- Sitecore Version
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/sitecore/shell/sitecore.version.xml',
        method = 'GET'
      },
      {
        path = '/sitecore/login/default.aspx',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<major>([^<]*)</major>.*<minor>([^<]*)</minor>.*<build>([^<]*)</build>.*<revision>([^<]*)</revision>',
        output = '\\1.\\2.\\3 (rev. \\4)'
      },
      {
        match = 'class="SystemInformationDivider">.*Sitecore.NET ([^<]*)</div>',
        output = '\\1'
      },
      {
        match = '<hr/>.*Sitecore version ([^<]*)</div>',
        output = '\\1'
      },
      {
        match = '',
        output = 'Sitecore.NET login page'
      }
    }
  });

-- Sitecore
table.insert(fingerprints, {
    category = 'cms',
    probes = {
      {
        path = '/sitecore/admin/stats.aspx', -- Removed in version 6.3.1 (rev. 110112)
        method = 'HEAD'
      },
      {
        path = '/sitecore/admin/unlock_admin.aspx', -- disabled per default in 6.2.0 (rev.100507)
        method = 'HEAD'
      },
      {
        path = '/sitecore/shell/Applications/shell.xml',
        method = 'HEAD'
      },
      {
        path = '/sitecore/admin/ShowConfig.aspx',
        method = 'HEAD'
      },
      {
        path = '/App_Config/Security/Domains.config.xml',
        method = 'HEAD'
      },
      {
        path = '/App_Config/Security/GlobalRoles.config.xml',
        method = 'HEAD'
      },
      {
        path = '/sitecore%20modules/staging/service/api.asmx',
        method = 'HEAD'
      },
      {
        path = '/sitecore%20modules/staging/workdir',
        method = 'HEAD'
      },
      {
        path = '/sitecore/system/Settings/Security/Profiles',
        method = 'HEAD'
      },

    },
    matches = {
      {
        match = '',
        output = 'Sitecore.NET (CMS)'
      }
    },
  });

local stdnse = require "stdnse"
local nmap = require "nmap"

nikto_db_path = stdnse.get_script_args("http-fingerprints.nikto-db-path") or "db_tests"
local f = nmap.fetchfile(nikto_db_path) or io.open(nikto_db_path, "r")

if f then

  stdnse.debug1("Found nikto db.")

  local nikto_db = {}
  for l in io.lines(nikto_db_path) do

    -- Skip comments.
    if not string.match(l, "^#.*") then

      record = {}

      for field in string.gmatch(l, "\"(.-)\",") do

        -- Grab every attribute and create a record.
        if field then
          string.gsub(field, '%%', '%%%%')
          table.insert(record, field)
        end
      end

      -- Make sure this record doesn't exists already.
      local exists = false
      for _, f in pairs(fingerprints) do
        if f.probes then
          for __, p in pairs(f.probes) do
            if p.path then
              if p.path == record[4] then
                exists = true
                break
              end
            end
          end
        end
      end

      -- What we have right now, is the following record:
      -- record[1]: Nikto test ID
      -- record[2]: OSVDB-ID
      -- record[3]: Server Type
      -- record[4]: URI
      -- record[5]: HTTP Method
      -- record[6]: Match 1
      -- record[7]: Match 1 (Or)
      -- record[8]: Match1 (And)
      -- record[9]: Fail 1
      -- record[10]: Fail 2
      -- record[11]: Summary
      -- record[12]: HTTP Data
      -- record[13]: Headers

      -- Is this a valid record?  Atm, with our current format we need
      -- to skip some nikto records. See NSEDoc for more info.

      if not exists
        and record[4]
        and record[8] == "" and record[10] == "" and record[12] == ""
        and (tonumber(record[4]) == nil or (tonumber(record[4]) and record[4] == "200")) then

        -- Our current format does not support HTTP code matching.
        if record[6] == "200" then record[6] = "" end

        nikto_fingerprint = { category = "nikto",
        probes = {
          {
            path = record[4],
            method = record[5]
          }
        },
        matches = {
          {
            dontmatch = record[9],
            match = record[6],
            output = record[11]
          },
        },
      }

      -- If there is a second match, add it.
      if record[7] and record[7] ~= "" then
        table.insert(nikto_fingerprint.matches, { match = record[7], output = record[11] })
      end

      table.insert(fingerprints, nikto_fingerprint)

    end
  end
end
end
