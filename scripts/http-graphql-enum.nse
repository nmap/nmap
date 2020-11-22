local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"

description = [[Enumerate GraphQL database schema via introspection]]

---
-- @usage
-- nmap --script http-graphql-enum --script-args http-graphql-enum.uri="/graphiql" <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-graphql-enum:
-- |   Object
-- |   => field1
-- |   ===> arg type
-- |   => field2 Type
-- |   ===> arg1
-- |   ===> arg2
-- |_  => field3
--
-- @args http-graphql-enum.uri path to GraphQL folder. Default: /graphql

author = "J. Igor Melo <jigordev@gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"}, "tcp")

local DEFAULT_GRAPHQL_URI = "/graphql"
local query = "fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}"

function string.starts(str, start)
	return string.sub(str, 1, string.len(start)) == start
end

action = function(host, port)
	local graphql_uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or DEFAULT_GRAPHQL_URI
	local path = graphql_uri .. "?query=" .. query
	local response = http.get(host, port, path)

	if not response or not response.status or response.status ~= 200 or not response.body then
		stdnse.debug1("Failed retrieve: %s", path)
		return
	end

	local ok_json, json_data = json.parse(response.body)

	if ok_json then
		local result = stdnse.output_table()
		for _, types in pairs(json_data["data"]["__schema"]["types"]) do
			result[#result + 1] = types["name"]

			if not string.starts(types["name"], "__") then
				for _, fields in pairs(types["fields"]) do
					local field_type = fields["type"]["ofType"]["name"] or ""
					result[#result + 1] = string.format("=> %s %s", fields["name"], field_type) 
					
					for _, args in pairs(fields["args"]) do
						local args_type = args["type"]["ofType"]["name"] or ""
						result[#result + 1] = string.format("===> %s %s", args["name"], args_type)
					end
				end
			end
		end
		return result
	end
	return
end
