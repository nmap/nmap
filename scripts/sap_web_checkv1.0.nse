description = [[
    Attemps to find vulnerable SAP Netweaber Portal, tha could allow disclose information
    (ident - port 80, 8080, 443, 5000) must be a web page http or https
]]
--

--@@usage nmap -p<port> --script sap_web_check.nse <target>
author = "Francisco Leon <@arphanetx>"
--Thanks to @nahualito for the debug time and pattient xD
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "default", "safe", "enum"}

local http = require "http"
local shortport = require "shortport"
local evil_path = "/irj/go/km/navigation?Uri=/"
local stdnse = require "stdnse"
portrule = shortport.http
local useragent = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"

action = function(host, port)
    local status_404, result_404, _= http.identify_404(host,port)
    if (status_404 and result_404 == 200 ) then
        stdnse.debug1("Exiting due to ambiguous response from web server on %s%:s.All URIs return status 200", host.ip, port.number)
        return nil
    end
    local options
    options = {header={}, no_cache=true, bypass_cache=true}
    options['header']['User-Agent'] = useragent
    local response = http.get(host, port,evil_path, options)
    if response and response.status == 200 then
        if string.find(response.body,'logon') then
            return string.format("Sap is not vulnerable")
        else
            local folder = " "
            local f_folder = "\n"
            local folders = string.format("SAP is vulnerable to anonymous user logon: %s%s\nFolders Found:", host.ip, evil_path)
            local body = response.body 
            while(folder ~= nil ) do
            --hard to figure out this regex, escape the chars as a case sensitive, [^$<] its to avoid the empty case
                folder = string.match(body, "[Cc][Ll][Aa][Ss][Ss][=][\"]urTxtStd[\"]>([^$<]*.)</[Ss][Pp][Aa][Nn]>")
                if folder ~= nil then
                  f_folder = f_folder..folder.."\n"
                   --we replace the word we need it with $, so we can look for the next case
                  body = string.gsub(body, folder, "$>")
                end
            end
            return string.format("%s%s",folders, f_folder)
        end
    else
        return string.format("Sap not found")
     end

end