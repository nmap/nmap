local mqtt = require "mqtt"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Dumps message traffic from MQTT brokers.

This script establishes a connection to an MQTT broker and subscribes
to the requested topics. The default topics have been chosen to
receive system information and all messages from other clients. This
allows Nmap, to listen to all messages being published by clients to
the MQTT broker.

For additional information:
* https://en.wikipedia.org/wiki/MQTT
* https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
]]

---
-- @usage nmap -p 1883 --script mqtt-subscribe <target>
--
-- @output
-- PORT     STATE SERVICE                 REASON
-- 1883/tcp open  mosquitto version 1.4.8 syn-ack
-- | mqtt-subscribe:
-- |   Topics and their most recent payloads:
-- |     $SYS/broker/load/publish/received/5min: 0.27
-- |     $SYS/broker/publish/messages/received: 7
-- |     $SYS/broker/heap/current: 39240
-- |     $SYS/broker/load/messages/sent/15min: 21.54
-- |     $SYS/broker/load/bytes/sent/5min: 647.13
-- |     $SYS/broker/clients/disconnected: 40
-- |     $SYS/broker/clients/connected: 1
-- |     $SYS/broker/subscriptions/count: 40
-- |     $SYS/broker/load/publish/received/15min: 0.46
-- |     $SYS/broker/clients/inactive: 40
-- |     $SYS/broker/messages/sent: 2318
-- |     $SYS/broker/load/publish/sent/1min: 2.48
-- |     $SYS/broker/load/sockets/1min: 0.09
-- |     $SYS/broker/load/connections/15min: 0.41
-- |     $SYS/broker/load/bytes/sent/15min: 822.79
-- |     $SYS/broker/load/sockets/15min: 0.81
-- |     $SYS/broker/version: mosquitto version 1.4.8
-- |     $SYS/broker/load/messages/received/5min: 1.24
-- |     $SYS/broker/load/publish/sent/15min: 20.39
-- |     $SYS/broker/uptime: 225478 seconds
-- |     $SYS/broker/load/publish/received/1min: 0.05
-- |     $SYS/broker/publish/messages/dropped: 0
-- |     $SYS/broker/retained messages/count: 47
-- |     $SYS/broker/messages/received: 293
-- |     $SYS/broker/load/connections/5min: 0.28
-- |     $SYS/broker/load/messages/sent/1min: 2.78
-- |     $SYS/broker/bytes/sent: 83026
-- |     $SYS/broker/load/bytes/received/5min: 13.98
-- |     $SYS/broker/load/messages/received/1min: 0.35
-- |     $SYS/broker/messages/stored: 47
-- |     $SYS/broker/publish/messages/sent: 2070
-- |     $SYS/broker/load/sockets/5min: 0.53
-- |     $SYS/broker/clients/active: 1
-- |     $SYS/broker/timestamp: Sun, 14 Feb 2016 15:48:26 +0000
-- |     $SYS/broker/load/bytes/received/15min: 17.83
-- |     $SYS/broker/publish/bytes/received: 49
-- |     $SYS/broker/load/publish/sent/5min: 16.03
-- |     $SYS/broker/publish/bytes/sent: 9752
-- |     $SYS/broker/load/bytes/sent/1min: 100.49
-- |     $SYS/broker/load/bytes/received/1min: 2.72
-- |     $SYS/broker/load/connections/1min: 0.06
-- |     $SYS/broker/clients/expired: 0
-- |     $SYS/broker/load/messages/received/15min: 1.49
-- |     $SYS/broker/load/messages/sent/5min: 17.00
-- |     $SYS/broker/bytes/received: 2520
-- |     $SYS/broker/heap/maximum: 41992
-- |_    $SYS/broker/clients/total: 41
--
-- @xmloutput
-- <table key="Topics and their most recent payloads">
--   <elem key="$SYS/broker/load/messages/sent/15min">23.48</elem>
--   <elem key="$SYS/broker/bytes/received">2469</elem>
--   <elem key="$SYS/broker/load/sockets/5min">0.63</elem>
--   <elem key="$SYS/broker/messages/sent">2268</elem>
--   <elem key="$SYS/broker/load/publish/sent/15min">22.25</elem>
--   <elem key="$SYS/broker/load/publish/received/1min">0.05</elem>
--   <elem key="$SYS/broker/load/bytes/sent/1min">626.45</elem>
--   <elem key="$SYS/broker/publish/messages/received">7</elem>
--   <elem key="$SYS/broker/load/connections/15min">0.39</elem>
--   <elem key="$SYS/broker/heap/current">38864</elem>
--   <elem key="$SYS/broker/load/sockets/1min">0.36</elem>
--   <elem key="$SYS/broker/messages/stored">47</elem>
--   <elem key="$SYS/broker/load/bytes/sent/15min">897.46</elem>
--   <elem key="$SYS/broker/version">mosquitto version 1.4.8</elem>
--   <elem key="$SYS/broker/clients/inactive">39</elem>
--   <elem key="$SYS/broker/subscriptions/count">39</elem>
--   <elem key="$SYS/broker/timestamp">Sun, 14 Feb 2016 15:48:26 +0000</elem>
--   <elem key="$SYS/broker/uptime">225280 seconds</elem>
--   <elem key="$SYS/broker/publish/bytes/sent">9520</elem>
--   <elem key="$SYS/broker/publish/messages/sent">2023</elem>
--   <elem key="$SYS/broker/load/bytes/received/1min">10.58</elem>
--   <elem key="$SYS/broker/load/connections/5min">0.31</elem>
--   <elem key="$SYS/broker/load/messages/received/15min">1.58</elem>
--   <elem key="$SYS/broker/publish/messages/dropped">0</elem>
--   <elem key="$SYS/broker/clients/connected">1</elem>
--   <elem key="$SYS/broker/load/messages/received/5min">1.51</elem>
--   <elem key="$SYS/broker/retained messages/count">47</elem>
--   <elem key="$SYS/broker/load/bytes/received/15min">18.78</elem>
--   <elem key="$SYS/broker/messages/received">289</elem>
--   <elem key="$SYS/broker/clients/disconnected">39</elem>
--   <elem key="$SYS/broker/load/publish/received/15min">0.46</elem>
--   <elem key="$SYS/broker/load/sockets/15min">0.82</elem>
--   <elem key="$SYS/broker/load/publish/sent/5min">21.44</elem>
--   <elem key="$SYS/broker/bytes/sent">81121</elem>
--   <elem key="$SYS/broker/publish/bytes/received">49</elem>
--   <elem key="$SYS/broker/load/connections/1min">0.18</elem>
--   <elem key="$SYS/broker/load/messages/received/1min">1.45</elem>
--   <elem key="$SYS/broker/clients/expired">0</elem>
--   <elem key="$SYS/broker/load/publish/received/5min">0.27</elem>
--   <elem key="$SYS/broker/load/messages/sent/5min">22.63</elem>
--   <elem key="$SYS/broker/load/bytes/received/5min">16.53</elem>
--   <elem key="$SYS/broker/load/messages/sent/1min">16.80</elem>
--   <elem key="$SYS/broker/clients/total">40</elem>
--   <elem key="$SYS/broker/clients/active">1</elem>
--   <elem key="$SYS/broker/load/publish/sent/1min">15.57</elem>
--   <elem key="$SYS/broker/load/bytes/sent/5min">863.85</elem>
--   <elem key="$SYS/broker/heap/maximum">41992</elem>
-- </table>
--
-- @args mqtt-subscribe.client-id MQTT client identifier, defaults to
--       <code>nmap</code> with a random suffix.
-- @args mqtt-subscribe.listen-msgs Number of PUBLISH messages to
--       receive, defaults to 100. A value of zero forces this script
--       to stop only when listen-time has passed.
-- @args mqtt-subscribe.listen-time Length of time to listen for
--       PUBLISH messages, defaults to 5s. A value of zero forces this
--       script to stop only when listen-msgs PUBLISH messages have
--       been received.
-- @args mqtt-subscribe.password Password for MQTT brokers requiring
--       authentication.
-- @args mqtt-subscribe.protocol-level MQTT protocol level, defaults
--       to 4.
-- @args mqtt-subscribe.protocol-name MQTT protocol name, defaults to
--       <code>MQTT</code>.
-- @args mqtt-subscribe.topic Topic filters to indicate which PUBLISH
--       messages we'd like to receive.
-- @args mqtt-subscribe.username Username for MQTT brokers requiring
--       authentication.

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.version_port_or_service({1883, 8883}, {"mqtt", "secure-mqtt"}, "tcp")

local function parse_args()
  local args = {}

  local protocol_level = stdnse.get_script_args(SCRIPT_NAME .. '.protocol-level')
  if protocol_level then
    -- Sanity check the value from the user.
    protocol_level = tonumber(protocol_level)
    if type(protocol_level) ~= "number" then
      return false, "protocol-level argument must be a number."
    elseif protocol_level < 0 or protocol_level > 255 then
      return false, "protocol-level argument must be in range between 0 and 255 inclusive."
    end
  else
    -- Indicate to the library that it should choose this on its own.
    protocol_level = false
  end
  args.protocol_level = protocol_level

  local protocol_name = stdnse.get_script_args(SCRIPT_NAME .. '.protocol-name')
  if protocol_name then
    -- Sanity check the value from the user.
    if type(protocol_name) ~= "string" then
      return false, "protocol-name argument must be a string."
    end
  else
    -- Indicate to the library that it can choose this on its own.
    protocol_name = false
  end
  args.protocol_name = protocol_name

  local client_id = stdnse.get_script_args(SCRIPT_NAME .. '.client-id')
  if not client_id then
    -- Indicate to the library that it should choose this on its own.
    client_id = false
  end
  args.client_id = client_id

  local max_msgs = stdnse.get_script_args(SCRIPT_NAME .. '.listen-msgs')
  if max_msgs then
    -- Sanity check the value from the user.
    max_msgs = tonumber(max_msgs)
    if type(max_msgs) ~= "number" then
      return false, "listen-msgs argument must be a number."
    elseif max_msgs < 0 then
      return false, "listen-msgs argument must be non-negative."
    end
  else
    -- Many brokers have ~50 $SYS/# messages, so we double that number
    -- for how many messages we'll receive.
    max_msgs = 100
  end
  args.max_msgs = max_msgs

  local max_time = stdnse.get_script_args(SCRIPT_NAME .. '.listen-time')
  if max_time then
    -- Convert the time specification from the CLI to seconds.
    local err
    max_time, err = stdnse.parse_timespec(max_time)
    if not max_time then
      return false, ("Unable to parse listen-time: %s"):format(err)
    elseif max_time < 0 then
      return false, "listen-time argument must be non-negative."
    elseif args.max_msgs == 0 and max_time == 0 then
      return false, "listen-time and listen-msgs may not both be zero."
    end
  else
    max_time = 5
  end
  args.max_time = max_time

  local username = stdnse.get_script_args(SCRIPT_NAME .. '.username')
  if not username then
    username = false
  end
  args.username = username

  local password = stdnse.get_script_args(SCRIPT_NAME .. '.password')
  if password then
    -- Sanity check the value from the user.
    if not username then
      return false, "A password cannot be given without also giving a username."
    end
  else
    password = false
  end
  args.password = password

  local topic = stdnse.get_script_args(SCRIPT_NAME .. '.topic')
  if topic then
    -- Sanity check the value from the user.
    if type(topic) ~= "table" then
      topic = {topic}
    end
  else
    -- These topic filters should receive most messages.
    topic = {"$SYS/#", "#"}
  end
  args.topic = topic

  return true, args
end

action = function(host, port)
  local output = stdnse.output_table()

  -- Parse and sanity check the command line arguments.
  local status, options = parse_args()
  if not status then
    output.ERROR = options
    return output, output.ERROR
  end

  -- Create an instance of the MQTT library's client object.
  local helper = mqtt.Helper:new(host, port)

  -- Connect to the MQTT broker.
  local status, response = helper:connect({
    ["protocol_level"] = options.protocol_level,
    ["protocol_name"] = options.protocol_name,
    ["client_id"] = options.client_id,
    ["username"] = options.username,
    ["password"] = options.password,
  })
  if not status then
    output.ERROR = response
    return output, output.ERROR
  elseif response.type ~= "CONNACK" then
    output.ERROR = ("Received control packet type '%s' instead of 'CONNACK'."):format(response.type)
    return output, output.ERROR
  elseif not response.accepted then
    output.ERROR = ("Connection rejected: %s"):format(response.reason)
    return output, output.ERROR
  end

  -- Build a list of topic filters.
  local filters = {}
  for _, filter in ipairs(options.topic) do
    table.insert(filters, {["filter"] = filter})
  end

  -- Subscribe to receive PUBLISH messages that match our topic
  -- filters.The MQTT standard allows sending PUBLISH messages before
  -- the SUBACK message, so we explicitly ignore any non-CONNACK
  -- messages at this point.
  local status, response = helper:request("SUBSCRIBE", {["filters"] = filters}, "SUBACK")
  if not status then
    output.ERROR = response
    return output, output.ERROR
  end

  -- For each topic to which we tried to subscribe, the MQTT broker
  -- informs us whether we were successful. We will note if any
  -- subscriptions fail, but continue so long as any succeeded.
  local success = false
  local results = response.filters
  for i, result in ipairs(results) do
    local topic = options.topic[i]
    if result.success then
      stdnse.debug3("Topic filter '%s' was accepted with a maximum QoS of %d.", topic, result.max_qos)
      success = true
    else
      stdnse.debug3("Topic filter '%s' was rejected.", topic)
    end
  end

  if not success then
    output.ERROR = "Every topic filter was rejected."
    return output, output.ERROR
  end

  -- We are now in a position to receive PUBLISH messages for at least
  -- one of our topic filters. We will record the topic of every
  -- PUBLISH message, but only retain the most recent payload.
  --
  -- We will continue to listen for PUBLISH messages until one of two
  -- conditions is met, whichever comes first:
  --   1) We have listened for max_time
  --   2) We have received max_msgs
  local end_time = nmap.clock_ms() + options.max_time * 1000
  local topics = {}
  local keys = {}
  local msgs = 0
  while true do
    -- Check for the first condition.
    local time_left = end_time - nmap.clock_ms()
    if time_left <= 0 then
      break
    end

    status, response = helper:receive({"PUBLISH"}, time_left / 1000)
    if not status then
      break
    end

    local name = response.topic
    if not topics[name] then
      table.insert(keys, name)
    end
    topics[name] = response.payload

    -- Check for the second condition.
    msgs = msgs + 1
    if options.max_msgs ~= 0 and msgs >= options.max_msgs then
      break
    end
  end

  -- Disconnect from the MQTT broker.
  helper:close()

  -- We're not going to error out if the last response was an error if
  -- there were successful responses before it, but we will log it.
  if not status then
    if #keys > 0 then
      stdnse.debug3("Received error while listening for PUBLISH messages: %s", response)
    else
      output.ERROR = response
      return output, output.ERROR
    end
  end

  -- Try and offer information on what software the MQTT broker is
  -- running through the version identification interface. Sadly this
  -- is often just a version number with no product name.
  local ver = topics["$SYS/broker/version"]
  if ver then
    port.version.name = ver
    nmap.set_port_version(host, port)
  end

  -- Format the topics and payloads we received.
  table.sort(keys)
  local topics_in_order = {}
  for _, key in ipairs(keys) do
    topics_in_order[key] = topics[key]
  end

  output["Topics and their most recent payloads"] = topics_in_order
  return output, stdnse.format_output(true, output)
end
