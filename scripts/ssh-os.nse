local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"

description = [[
Identifies Ubuntu, FreeBSD, Debian, or Raspbian version based on response of SSH banner.  

Identifies the following versions:

Ubuntu 4.10 to 20.10
FreeBSD 4.3 to 12.2-RELEASE
Debian 3.x to 11.x (tentative 11.x version recognition)
Raspbian 7.x to 11.x (tentative 11.x version recognition)


Note: The accuracy of the response is based on the default banner response.
A number of scenarios may provide an inaccurate result from the target host:

* different OpenSSH version or alternative SSH server installed
* edited/omitted banner via sshd_config
* hexedit of OpenSSH binary; modified banner
* recompiled OpenSSH

]]

-- @usage 
-- nmap -p22 -sV --script ssh-os.nse <target>
--   OR
-- nmap -p <port number> -sV --script ssh-os.nse <target>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
--22/tcp open  ssh     syn-ack OpenSSH 6.0p1 Debian 3ubuntu1.2 (Ubuntu Linux; protocol 2.0)
--| ssh-os:
--|   Linux Version: Ubuntu 12.10 Quantal Quetzal
--|   SSH Version + Build Number: 6.0p1-3
--|_  SSH Banner: SSH-2.0-OpenSSH_6.0p1 Debian-3ubuntu1.2\x0D
--Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
--
--
--
-- List of default banners for reference:
-- https://github.com/richlamdev/ssh-default-banners
-- https://github.com/rapid7/recog/blob/master/xml/ssh_banners.xml
--
-- SSH Banner format: RFC 4253
-- https://tools.ietf.org/html/rfc4253
-- 
--
-- Typical Ubuntu SSH version banner:
--    SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.1
--
-- Breakdown:
--
-- SSH Proto Ver   OpenSSH Ver   Portable Ver   Build Ver   Patch Ver
-- SSH-2.0         OpenSSH_5.9   p1             Debian-5    ubuntu1.1

author = "Richard Lam <richlam.dev at gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

---
-- obtain SSH+portable+build versions to identify Ubuntu version.
-- @param ssh_banner to be evaluated against regex
-- @return Ubuntu version and build number
local function get_ubuntu(ssh_banner)

  local ubuntu_ver =""
  local u_ssh_build = ""
  local u_build_version = ""
  local u_ssh_version = ""
  
-- start the match at 17 chars; typically: SSH-2.0-OpenSSH_

-- identify longer SSH version length, eg. 6.6.1p1 
  if ssh_banner:match("%d%.%d%.%dp%d+",17) then
    u_ssh_version = ssh_banner:match("%d%.%d%.%dp%d+",17) 
  else                                            
-- identify shorter SSH version length eg. 6.6p2
    u_ssh_version = ssh_banner:match("%d%.%dp%d+",17) 
  end
	  
-- add 8 characters for _Ubuntu- or _Debian- to obtain build number
  local start_offset = 16 + string.len(u_ssh_version) + 8

-- obtain build version and concat to SSH version, then lookup version
  u_build_version = ssh_banner:match("%-%d+",start_offset)
  u_ssh_build = u_ssh_version .. u_build_version

-- https://github.com/richlamdev/ssh-default-banners
  local u_table = {
    ["8.3p1-1"] = "Ubuntu 20.10 Groovy Gorilla",
    ["8.2p1-4"] = "Ubuntu 20.04 Focal Fossa",
    ["8.0p1-6"] = "Ubuntu 19.10 Eoan Ermine",
    ["7.9p1-10"] = "Ubuntu 19.04 Disco Dingo",
    ["7.7p1-4"] = "Ubuntu 18.10 Cosmic Cuttlefish",
    ["7.6p1-4"] = "Ubuntu 18.04 Bionic Beaver",
    ["7.5p1-10"] = "Ubuntu 17.10 Artful Aardvark",
    ["7.4p1-10"] = "Ubuntu 17.04 Zesty Zapus",
    ["7.3p1-1"] = "Ubuntu 16.10 Yakkety Yak",
    ["7.2p2-4"] = "Ubuntu 16.04 Xenial Xerus",
    ["6.9p1-2"] = "Ubuntu 15.10 Wily Werewolf",
    ["6.7p1-5"] = "Ubuntu 15.04 Vivid Vervet",
    ["6.6.1p1-8"] = "Ubuntu 14.10 Utopic Unicorn",
    ["6.6.1p1-2"] = "Ubuntu 14.04 Trusty Tahr",
    ["6.2p2-6"] = "Ubuntu 13.10 Saucy Salamander",
    ["6.1p1-4"] = "Ubuntu 13.04 Raring Ringtail",
    ["6.0p1-3"] = "Ubuntu 12.10 Quantal Quetzal",
    ["5.9p1-5"] = "Ubuntu 12.04 Precise Pangolin",
    ["5.8p1-7"] = "Ubuntu 11.10 Oneiric Ocelot",
    ["5.8p1-1"] = "Ubuntu 11.04 Natty Narwhal",
    ["5.5p1-4"] = "Ubuntu 10.10 Maverick Meerkat",
    ["5.3p1-3"] = "Ubuntu 10.04 Lucid Lynx",
    ["5.1p1-6"] = "Ubuntu 9.10 Karmic Koala",
    ["5.1p1-5"] = "Ubuntu 9.04 Jaunty Jackalope",
    ["5.1p1-3"] = "Ubuntu 8.10 Intrepid Ibex",
    ["4.7p1-8"] = "Ubuntu 8.04 Hardy Heron",
    ["4.6p1-5"] = "Ubuntu 7.10 Gutsy Gibbon",
    ["4.3p2-8"] = "Ubuntu 7.04 Feisty Fawn",
    ["4.3p2-5"] = "Ubuntu 6.10 Edgy Eft",
    ["4.2p1-7"] = "Ubuntu 6.06 Dapper Drake",
    ["4.1p1-7"] = "Ubuntu 5.10 Breezy Badger",
    ["3.9p1-1"] = "Ubuntu 5.04 Hoary Hedgehog",
    ["3.8.1p1-11"] = "Ubuntu 4.10 Warty Warthog"
  }
  
  if u_table[u_ssh_build] then
    ubuntu_ver = u_table[u_ssh_build] 
  else
    ubuntu_ver = "Unknown Ubuntu version"
  end 

  return ubuntu_ver,u_ssh_build
end

---
-- obtain last eight digits(date) of banner to identify FreeBSD version.
-- @param ssh_banner to be evaluated against regex
-- @return FreeBSD version
local function get_freebsd(ssh_banner)

  local freebsd_ver = ""
  local f_ssh_version = ""
  
  -- determine longer banner with hpn13v11
  if ssh_banner:match("hpn13v11",17) then
    f_ssh_version = ssh_banner:match("%d+",37)
  else
    f_ssh_version = ssh_banner:match("%d+",28) 
  end
	  
-- https://github.com/richlamdev/ssh-default-banners
  local f_table = {
    ["20200214"] = "FreeBSD 12.2-RELEASE",
    ["20180909"] = "FreeBSD 12.0, or 12.1-RELEASE",
    ["20170903"] = "FreeBSD 11.2, or 11.3-RELEASE",
    ["20161230"] = "FreeBSD 11.1-RELEASE",
    ["20160310"] = "FreeBSD 11.0-RELEASE",
    ["20170902"] = "FreeBSD 10.4-RELEASE",
    ["20160310"] = "FreeBSD 10.3-RELEASE",
    ["20140420"] = "FreeBSD 10.1, or 10.2-RELEASE",
    ["20131111"] = "FreeBSD 10.0-RELEASE",
    ["20140420"] = "FreeBSD 9.3-RELEASE",
    ["20130515"] = "FreeBSD 9.2-RELEASE",
    ["20110503"] = "FreeBSD 9.0, or 9.1-RELEASE",
    ["20120901"] = "FreeBSD 8.4-RELEASE",
    ["20100308"] = "FreeBSD 8.1, or 8.2, or 8.3-RELEASE",
    ["20090522"] = "FreeBSD 8.0-RELEASE",
    ["20080901"] = "FreeBSD 7.1, or 7.2, or 7.3 or 7.4-RELEASE",
    ["20061110"] = "FreeBSD 6.2, or 6.3, or 6.4, or 7.0-RELEASE",
    ["20050903"] = "FreeBSD 6.0, or 6.1-RELEASE",
    ["20060123"] = "FreeBSD 5.5-RELEASE",
    ["20040419"] = "FreeBSD 5.3-RELEASE, or 5.4-RELEASE",
    ["20030924"] = "FreeBSD 5.2-RELEASE",
    ["20030423"] = "FreeBSD 5.1-RELEASE",
    ["20021029"] = "FreeBSD 5.0-RELEASE",
    ["20030924"] = "FreeBSD 4.9, or 4.10, or 4.11-RELEASE",
    ["20030201"] = "FreeBSD 4.8-RELEASE",
    ["20020702"] = "FreeBSD 4.6.2-RELEASE, or 4.7-RELEASE",
    ["20020307"] = "FreeBSD 4.6-RELEASE",
    ["20011202"] = "FreeBSD 4.5-RELEASE",
    ["20010713"] = "FreeBSD 4.4-RELEASE",
    ["20010321"] = "FreeBSD 4.3-RELEASE"
  }

  if f_table[f_ssh_version] then
    freebsd_ver = f_table[f_ssh_version]
  else
    freebsd_ver = "Unknown FreeBSD version"
  end

  return freebsd_ver
end

---
-- obtain SSH+portable+build versions to identify Debian or Raspbian version.
-- @param ssh_banner to be evaluated against regex
-- @return Debian version and build number
local function get_debian(ssh_banner)

  local debian_ver =""
  local d_ssh_build = ""
  local d_build_version = ""
  local d_ssh_version = ""
  local start_offset = ""

-- start the match at 17 chars; typically: SSH-2.0-OpenSSH_

-- identify longer SSH version length, eg. 6.6.1p1 
  if ssh_banner:match("%d%.%d%.%dp%d+",17) then
    d_ssh_version = ssh_banner:match("%d%.%d%.%dp%d+",17) 
  else                                            
-- identify shorter SSH version length eg. 6.6p2
    d_ssh_version = ssh_banner:match("%d%.%dp%d+",17) 
  end
	  
-- add 8 for Debian, or 10 for Raspbian to obtain build number
  if ssh_banner:match ("Debian",22) then
    start_offset = 16 + string.len(d_ssh_version) + 8
  elseif ssh_banner:match ("Raspbian",22) then
    start_offset = 16 + string.len(d_ssh_version) + 10
  end

-- obtain build version and concat to SSH version, then lookup version
  d_build_version = ssh_banner:match("%-%d+",start_offset)
  d_ssh_build = d_ssh_version .. d_build_version

-- https://github.com/richlamdev/ssh-default-banners
  local d_table = {
    ["8.1p1-1"] = "Debian 11.x \"Bullseye\" based",
    ["7.9p1-10"] = "Debian 10.x \"Buster\" based",
    ["7.4p-10"] = "Debian 9.x \"Stretch\" based",
    ["7.4p-9"] = "Debian 9.x \"Stretch\" based",
    ["6.7p1-5"] = "Debian 8.x \"Jessie\" based",
    ["6.0p1-4"] = "Debian 7.x \"Wheezy\" based",
    ["6.0p1-2"] = "Debian 7.x \"Wheezy\" based",
    ["5.8p1-4"] = "Debian 6.x \"Squeeze\" based",
    ["5.5p1-6"] = "Debian 6.x \"Squeeze\" based",
    ["5.1p1-5"] = "Debian 5.x \"Lenny\" based",
    ["4.3p2-9"] = "Debian 4.x \"Etch\" based",
    ["3.8.1p1-8"] = "Debian 3.1 \"Woody\" based",
    ["3.4p1-1"] = "Debian 3.0 \"Woody\" based"
  }

  if d_table[d_ssh_build] then
    debian_ver = d_table[d_ssh_build]
  else
    debian_ver = "Unknown Debian based (or Raspbian) version"
  end

  return debian_ver,d_ssh_build
end


portrule = shortport.port_or_service( 22 , "ssh", "tcp", "open")

action = function (host, port)

  local distro_type =""
  local ssh_build = ""
  local misc_os_type = ""
  local response = stdnse.output_table()
  
  local ssh_status, ssh_banner = comm.get_banner(host, port, {lines=1}) 
  if not ssh_status then
    return
  end

  -- OpenSSH based identification
  if ssh_banner:match("OpenSSH_",7) then

    if ssh_banner:match("[uU]buntu",17) then
      distro_type,ssh_build = get_ubuntu(ssh_banner)
      response["Linux Version"] = distro_type
      response["SSH Version + Build Number"] = ssh_build
  
    -- Ubuntu 13.04 is the only version that does not have the string 
    -- "[uU]buntu" embedded in the SSH version banner
    -- (Also, Debian does not have a version released with OpenSSH 6.1p1) 
    elseif ssh_banner:match("6%.1p1%sDebian%-",17) then
      distro_type,ssh_build = get_ubuntu(ssh_banner)
      response["Linux Version"] = distro_type
      response["SSH Version + Build Number"] = ssh_build
  
    elseif ssh_banner:match("FreeBSD",20) then
      distro_type = get_freebsd(ssh_banner)
      response["BSD Version"] = distro_type
  
    elseif (ssh_banner:match("Debian", 22)) or (ssh_banner:match("Raspbian", 22)) then
      distro_type,ssh_build = get_debian(ssh_banner)
      response["Linux Version"] = distro_type
      response["SSH Version + Build Number"] = ssh_build
    end

  else --potential to identify non-OpenSSH banners in the future
    distro_type = "Unrecognized SSH banner."
    response["Linux/Unix Version"] = distro_type
  end

  response["SSH Banner"] = ssh_banner

  return response
end
