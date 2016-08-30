local amqp = require "amqp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Gathers information (a list of all server properties) from an AMQP (advanced message queuing protocol) server.

See http://www.rabbitmq.com/extensions.html for details on the
<code>server-properties</code> field.
]]

---
-- @usage
-- nmap --script amqp-info -p5672 <target>
---
-- @args amqp.version Can be used to specify the client version to use (currently, 0-8, 0-9 or 0-9-1)
--
-- @output
-- 5672/tcp open  amqp
-- | amqp-info:
-- |   capabilities:
-- |     publisher_confirms: YES
-- |     exchange_exchange_bindings: YES
-- |     basic.nack: YES
-- |     consumer_cancel_notify: YES
-- |   copyright: Copyright (C) 2007-2011 VMware, Inc.
-- |   information: Licensed under the MPL.  See http://www.rabbitmq.com/
-- |   platform: Erlang/OTP
-- |   product: RabbitMQ
-- |   version: 2.4.0
-- |   mechanisms: PLAIN AMQPLAIN
-- |_  locales: en_US

author = "Sebastian Dragomir"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe", "version"}


portrule = shortport.version_port_or_service(5672, "amqp", "tcp", "open")

action = function(host, port)
  local cli = amqp.AMQP:new( host, port )

  local status, data = cli:connect()
  if not status then return "Unable to open connection: " .. data end

  status, data = cli:handshake()
  if not status then return data end

  cli:disconnect()

  port.version.name = "amqp"
  port.version.product = cli:getServerProduct()
  port.version.extrainfo = cli:getProtocolVersion()
  port.version.version = cli:getServerVersion()
  nmap.set_port_version(host, port)

  return stdnse.format_output(status, cli:getServerProperties())
end
