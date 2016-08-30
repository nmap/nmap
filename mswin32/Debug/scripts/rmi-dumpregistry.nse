local nmap = require "nmap"
local rmi = require "rmi"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Connects to a remote RMI registry and attempts to dump all of its
objects.

First it tries to determine the names of all objects bound in the
registry, and then it tries to determine information about the
objects, such as the the class names of the superclasses and
interfaces. This may, depending on what the registry is used for, give
valuable information about the service. E.g, if the app uses JMX (Java
Management eXtensions), you should see an object called "jmxconnector"
on it.

It also gives information about where the objects are located, (marked
with @<ip>:port in the output).

Some apps give away the classpath, which this scripts catches in
so-called "Custom data".
]]

---
-- @usage nmap --script "rmi-dumpregistry.nse" -p 1098 <host>
-- @output
-- PORT     STATE SERVICE  REASON
-- 1099/tcp open  java-rmi syn-ack
-- | rmi-dumpregistry:
-- |   jmxrmi
-- |     javax.management.remote.rmi.RMIServerImpl_Stub
-- |     @127.0.1.1:40353
-- |     extends
-- |       java.rmi.server.RemoteStub
-- |       extends
-- |_        java.rmi.server.RemoteObject
--
-- @output
-- PORT     STATE SERVICE  REASON
-- 1099/tcp open  java-rmi syn-ack
-- | rmi-dumpregistry:
-- |   cfassembler/default
-- |     coldfusion.flex.rmi.DataServicesCFProxyServer_Stub
-- |     @192.168.0.3:1271
-- |     extends
-- |       java.rmi.server.RemoteStub
-- |       extends
-- |         java.rmi.server.RemoteObject
-- |     Custom data
-- |       Classpath
-- |         file:/C:/CFusionMX7/runtime/../lib/ant-launcher.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ant.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/axis.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/backport-util-concurrent.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/bcel.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cdo.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cdohost.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cf4was.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cf4was_ae.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cfmx-ssl.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/cfusion.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-beanutils-1.5.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-collections-2.1.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-digester-1.3.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-digester-1.7.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-discovery-0.2.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-discovery.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-logging-1.0.2.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-logging-api-1.0.2.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/commons-net-1.2.2.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/crystal.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flashgateway.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flashremoting_update.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flex-assemblerservice.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flex-messaging-common.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flex-messaging-opt.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flex-messaging-req.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/flex-messaging.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/httpclient.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ib61patch.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ib6addonpatch.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ib6core.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ib6swing.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ib6util.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/im.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/iText.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/iTextAsian.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/izmado.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/jakarta-oro-2.0.6.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/java2wsdl.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/jaxrpc.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/jdom.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/jeb.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/jintegra.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ldap.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ldapbp.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/log4j.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/macromedia_drivers.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/mail.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/msapps.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/pbclient42RE.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/pbembedded42RE.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/pbserver42RE.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/pbtools42RE.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/poi-2.5.1-final-20040804.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/poi-contrib-2.5.1-final-20040804.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/ri_generic.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/saaj.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/smack.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/smpp.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/STComm.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/tools.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/tt-bytecode.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/vadmin.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/verity.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/vparametric.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/vsearch.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/wc50.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/webchartsJava2D.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/wsdl2java.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/wsdl4j-1.5.1.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/wsdl4j.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/xalan.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/xercesImpl.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/xml-apis.jar
-- |         file:/C:/CFusionMX7/runtime/../lib/
-- |         file:/C:/CFusionMX7/runtime/../gateway/lib/examples.jar
-- |         file:/C:/CFusionMX7/runtime/../gateway/lib/
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/batik-awt-util.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/batik-css.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/batik-ext.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/batik-transcoder.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/batik-util.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/commons-discovery.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/commons-logging.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/concurrent.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/flex.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/jakarta-oro-2.0.7.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/jcert.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/jnet.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/jsse.jar
-- |         file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/oscache.jar
-- |_        file:/C:/CFusionMX7/runtime/../wwwroot/WEB-INF/cfform/jars/
--
--
--@version 0.5

author = "Martin Holst Swende"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({1098, 1099, 1090, 8901, 8902, 8903}, {"java-rmi", "rmiregistry"})

-- Some lazy shortcuts

local function dbg(str,...)
  stdnse.debug3("RMI-DUMPREG:"..str, ...)
end

local function dbg_err(str, ... )
  stdnse.debug1("RMI-DUMPREG-ERR:"..str, ...)
end

-- Function to split a string
local function split(str, sep)
  local sep, fields = sep or "; ", {}
  local pattern = string.format("([^%s]+)", sep)
  str:gsub(pattern, function(c) fields[#fields+1] = c end)
  return fields
end


--This is a customData formatter. In some cases, the RMI library finds 'custom data' which belongs to an object.
-- This data is not handled correctly, instead, the data is dumped in the objects customData field (which is a table with strings)
-- The RMI library does not do anything more than that - however, here in the land of rmi-dumpregistry land, we may have
-- more knowledge about how to interpret that data.
-- In the wild, coldfusion.flex.rmi.DataServicesCFProxyServer_Stub e.g discloses the classpath in this variable. This method looks at
-- the contents of the custom data. if it looks like a class path, we display it as such. This method is passed to the toTable() method
-- of the returned RMI object.
-- @return title, data
function customDataFormatter(className, customData)
  if customData == nil then return nil end
  if #customData == 0 then return nil end

  local retData = {}
  for k,v in ipairs(customData) do
    if v:find("file:/") == 1 then
      -- This is a classpath
      local cp = split(v, "; ") -- Splits into table
      table.insert(retData, "Classpath")
      table.insert(retData, cp)
    else
      table.insert(retData[v])
    end
  end

  return "Custom data", retData
end


function action(host,port, args)
  local registry = rmi.Registry:new( host, port )

  local status, j_array = registry:list()
  local output = {}
  if not status then
    table.insert(output, ("Registry listing failed (%s)"):format(tostring(j_array)))
    return stdnse.format_output(false, output)
  end
  -- It's definitely RMI!
  port.version.name = 'java-rmi'
  port.version.product = 'Java RMI Registry'
  nmap.set_port_version(host,port)

  -- Monkey patch the java-class in rmi, to set our own custom data formatter
  -- for classpaths
  rmi.JavaClass.customDataFormatter = customDataFormatter

  -- We expect an array of strings to be the return data
  local data = j_array:getValues()
  for i,name in ipairs( data ) do
    --print(data)
    table.insert(output, name)
    dbg("Querying object %s", name)
    local status, j_object = registry:lookup(name)

    if status then
      table.insert(output, j_object:toTable())
    end
  end

  return stdnse.format_output(true, output)
end
