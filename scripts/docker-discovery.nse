local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Retrieves information about all Docker Containers, Images, Networks, Volumes and Plugins present on the machine]]

---
-- @usage
-- nmap --script docker-discovery <host>
--
-- @output
-- PORT     STATE SERVICE
-- 2375/tcp open  docker
-- | docker-discovery: 
-- |   Containers: 
-- |     Name: /relaxed_swanson
-- |     Id: 7ed0920aff9dcd5064226eb35a44a5b4df9f74ca8cb6a20494f15914c9ca9b7b
-- |     Image: mongo
-- |     Command: docker-entrypoint.sh mongod
-- |     State: created
-- |     Status: Created
-- | 
-- |   Images: 
-- |     Id: sha256:d70eaf7277daba18aca944dr410e7e4dd97c1262c064d2b101c500caa4decaf1
-- |     RepoTags: mongo:latest
-- |     Created: 1603474356
-- |     Size: 492141820
-- |     VirtualSize: 492141820
-- |     Containers: 1
-- | 
-- |   Networks: 
-- |     Name: bridge
-- |     Id: 97897b7c8bd8a877aa5db1bbbb0a829827cfd3b7a966e5d484f8109533d8e637
-- |     Created: 2020-11-06T19:34:27.047142296-03:00
-- |     Scope: local
-- |     Driver: bridge
-- | 
-- |     Name: none
-- |     Id: abe223dc1bd7e073f6fe7ccf013e40e65bb34523bce4644b8915fbd5a4ef0f15
-- |     Created: 2020-11-04T02:56:57.613506062-03:00
-- |     Scope: local
-- |     Driver: null
-- | 
-- |     Name: host
-- |     Id: e16b63f33c31a3cf33abfa4c557f8e506bb8494503bd55a32ca86d63c880c50c
-- |     Created: 2020-11-04T02:56:57.780274463-03:00
-- |     Scope: local
-- |_    Driver: host


author = "J. Igor Melo <jigordev@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}

portrule = shortport.version_port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

build_request = function(host, port, path)
	local response = http.get(host, port, path)
	if not response or not response.status or response.status ~= 200 or not response.body then
		stdnse.debug1("Failde to retrieve: %s", path)
		return
	end

	local ok_json, json_data = json.parse(response.body)

	if ok_json and #json_data > 0 then
		return json_data
	end
	return
end

get_version = function(host, port)
	local path = "/info"
	local json_data = build_request(host, port, path)

	if json_data then
		return json_data["Version"]
	end
	return
end

get_containers = function(host, port)
	local path = "/containers/json?all=1"
	local json_data = build_request(host, port, path)

	if json_data then
		local containers = {}
		for _, items in pairs(json_data) do
			containers[#containers + 1] = "Name: " .. table.concat(items["Names"], ", ")
			containers[#containers + 1] = "Id: " .. items["Id"]
			containers[#containers + 1] = "Image: " .. items["Image"]
			containers[#containers + 1] = "Command: " .. items["Command"]
			containers[#containers + 1] = "State: " .. items["State"]
			containers[#containers + 1] = "Status: " .. items["Status"] .. "\n"
		end
		return containers
	end
	return
end

get_images = function(host, port)
	local path = "/images/json?all=1"
	local json_data = build_request(host, port, path)

	if json_data then
		local images = {}
		for _, items in pairs(json_data) do
			images[#images + 1] = "Id: " .. items["Id"]
			images[#images + 1] = "RepoTags: " .. table.concat(items["RepoTags"], ", ")
			images[#images + 1] = "Created: " .. items["Created"]
			images[#images + 1] = "Size: " .. items["Size"]
			images[#images + 1] = "VirtualSize: " .. items["VirtualSize"]
			images[#images + 1] = "Containers:" .. items["Containers"] .. "\n"
		end
		return images
	end
	return
end

get_networks = function(host, port)
	local path = "/networks"
	local json_data = build_request(host, port, path)

	if json_data then
		local networks = {}
		for _, items in pairs(json_data) do
			networks[#networks + 1] = "Name: " .. items["Name"]
			networks[#networks + 1] = "Id: " .. items["Id"]
			networks[#networks + 1] = "Created: " .. items["Created"]
			networks[#networks + 1] = "Scope: " .. items["Scope"]
			networks[#networks + 1] = "Driver: " .. items["Driver"] .. "\n"
		end
		return networks
	end
	return
end

get_volumes = function(host, port)
	local path = "/volumes"
	local json_data = build_request(host, port, path)

	if json_data then
		local volumes = {}
		for _, items in pairs(json_data["Volumes"]) do
			volumes[#volumes + 1] = "Name: " .. items["Name"]
			volumes[#volumes + 1] = "Created: " .. items["CreatedAt"]
			volumes[#volumes + 1] = "Driver: " .. items["Driver"]
			volumes[#volumes + 1] = "MountPoint: " .. items["Mountpoint"]
			volumes[#volumes + 1] = "Scope: " .. items["Scope"] .. "\n"
		end
		return volumes
	end
	return
end

get_plugins = function(host, port)
	local path = "/plugins"
	local json_data = build_request(host, port, path)

	if json_data then
		print(json_data)
		local plugins = {}
		for _, items in pairs(json_data) do
			plugins[#plugins + 1] = "Name: " .. items["Name"]
			plugins[#plugins + 1] = "Id: " .. items["Id"]
			plugins[#plugins + 1] = "Enabled: " .. items["Enabled"]
			plugins[#plugins + 1] = "Plugin Reference: " .. items["PluginReference"]
			plugins[#plugins + 1] = "Docker Version: " .. items["Config"]["DockerVersion"]
			plugins[#plugins + 1] = "Description: " .. items["Config"]["Description"]
			plugins[#plugins + 1] = "Documentation: " .. items["Config"]["Documentation"] .. "\n"
		end
		return plugins
	end
	return
end

action = function(host, port)
	local output = stdnse.output_table()
	output.Containers = get_containers(host, port)
	output.Images = get_images(host, port)
	output.Networks = get_networks(host, port)
	output.Volumes = get_volumes(host, port)
	output.Plugins = get_plugins(host, port)

	local version = get_version(host, port)
	port.version.name = "docker"
	port.version.version = version
	port.version.product = "Docker"
	nmap.set_port_version(host, port)
	return output
end
