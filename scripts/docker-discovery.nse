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
-- |     
-- |       ImageID: sha256:ba0c2ff8d3620d0910832423efef02787214013b1c5b1d9dc9d87d638e2ceb71
-- |       State: created
-- |       Id: 7ed0920aff9dcd5064226eb35a44ab44df9f74ca8cb6a2049471591439ca9b7b
-- |       Image: mongo
-- |       Mounts-1-RW: true
-- |       Mounts-1-Type: volume
-- |       Mounts-1-Driver: local
-- |       Mounts-1-Destination: /data/configdb
-- |       Mounts-1-Name: 5fef582298433627aa56fff01c87549cd59a52e4701fdf05882ff0236ffa63ca
-- |       Mounts-2-RW: true
-- |       Mounts-2-Type: volume
-- |       Mounts-2-Driver: local
-- |       Mounts-2-Destination: /data/db
-- |       Mounts-2-Name: 41a0f68c93d267a8546730b7ecb00179373b25426f3c8ae7e4f5fb05207bb75f
-- |       HostConfig-NetworkMode: default
-- |       NetworkSettings-Networks-bridge-GlobalIPv6PrefixLen: 0
-- |       NetworkSettings-Networks-bridge-IPPrefixLen: 0
-- |       Command: docker-entrypoint.sh mongod
-- |       Names-1: /relaxed_swanson
-- |       Created: 1604755552
-- |       Status: Created
-- |     
-- |       ImageID: sha256:eb40dcf64078249a33f68fdd8d80624cb81b524c24f50b95fff5c2b40b4c3fdc
-- |       State: created
-- |       Id: ff5cafb9cf5af334fc0ddfb0f30dc9a6036dd0f2b83c40453f0b3200967391a6
-- |       Image: django
-- |       HostConfig-NetworkMode: default
-- |       NetworkSettings-Networks-bridge-GlobalIPv6PrefixLen: 0
-- |       NetworkSettings-Networks-bridge-IPPrefixLen: 0
-- |       Command: python3
-- |       Names-1: /youthful_napier
-- |       Created: 1604755503
-- |       Status: Created
-- |   Images: 
-- |     
-- |       SharedSize: -1
-- |       Id: sha256:d70eaf7277eada08fca944de400e7e4dd97b1262c06ed2b10115304aa4decaf1
-- |       VirtualSize: 72879481
-- |       RepoDigests-1: ubuntu@sha256:fff16eea1a8ae92867721d90c59a75652ea66d29c05694e6e2f898704bdb8cf1
-- |       Containers: -1
-- |       Created: 1603474356
-- |       Size: 72879481
-- |       RepoTags-1: ubuntu:latest
-- |     
-- |       SharedSize: -1
-- |       Id: sha256:ba0c2ff8d3620c0910832424efef02787214013b1c5b1d9dc9d874638e2cec71
-- |       VirtualSize: 492141820
-- |       RepoDigests-1: mongo@sha256:efc408845bc917d0b7fd97a8590e9c8d3c314f58cee651bd3030c9cf2ce8032d
-- |       Containers: -1
-- |       Created: 1601082258
-- |       Size: 492141820
-- |       RepoTags-1: mongo:latest
-- |     
-- |       SharedSize: -1
-- |       Id: sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26f99317c745f6b
-- |       VirtualSize: 13336
-- |       RepoDigests-1: hello-world@sha256:8c5aeeb6a5f3ba4883347d3747a7249f491765ca1caa4765da5dfcf6b9b717c0
-- |       Containers: -1
-- |       Created: 1578014497
-- |       Size: 13336
-- |       RepoTags-1: hello-world:latest
-- |     
-- |       SharedSize: -1
-- |       Id: sha256:eb40dcf64078249a33f68fdd8d80624cb81b724c24f50b95fff5c2b46bdc3fdc
-- |       VirtualSize: 436117187
-- |       RepoDigests-1: django@sha256:5bfd3f44295246395b897188b7f43cfcd6c2f631a017ee2a6fca3cb8992501e8
-- |       Containers: -1
-- |       Created: 1482165234
-- |       Size: 436117187
-- |       RepoTags-1: django:latest
-- |   Networks: 
-- |     
-- |       Internal: false
-- |       Id: abe223d31bd7e073f6fe7ccb014e40e55bb345235ce4664b8915fbd3e4ef0f15
-- |       IPAM-Driver: default
-- |       ConfigOnly: false
-- |       Ingress: false
-- |       EnableIPv6: false
-- |       Attachable: false
-- |       Scope: local
-- |       Driver: null
-- |       Created: 2020-11-04T02:56:57.613506062-03:00
-- |       Name: none
-- |     
-- |       Internal: false
-- |       Id: e16b63f33c21a3c133aafa4c556f8e306bb8494533bd59a32ca86d68d880c50c
-- |       IPAM-Driver: default
-- |       ConfigOnly: false
-- |       Ingress: false
-- |       EnableIPv6: false
-- |       Attachable: false
-- |       Scope: local
-- |       Driver: host
-- |       Created: 2020-11-04T02:56:57.780274463-03:00
-- |       Name: host
-- |     
-- |       Internal: false
-- |       Id: 266ffe98f5438876bf1abe7cd4bb1c5dc0c01b0a8667a11b188d3dd39fe4b167
-- |       Options-com.docker.network.bridge.host_binding_ipv4: 0.0.0.0
-- |       Options-com.docker.network.bridge.default_bridge: true
-- |       Options-com.docker.network.bridge.enable_ip_masquerade: true
-- |       Options-com.docker.network.bridge.name: docker0
-- |       Options-com.docker.network.driver.mtu: 1500
-- |       Options-com.docker.network.bridge.enable_icc: true
-- |       IPAM-Driver: default
-- |       IPAM-Config-1-Subnet: 172.17.0.0/16
-- |       IPAM-Config-1-Gateway: 172.17.0.1
-- |       ConfigOnly: false
-- |       Ingress: false
-- |       EnableIPv6: false
-- |       Attachable: false
-- |       Scope: local
-- |       Driver: bridge
-- |       Created: 2020-11-09T16:24:52.527465445-03:00
-- |       Name: bridge
-- |   Volumes: 
-- |     
-- |       Scope: local
-- |       CreatedAt: 2020-11-04T03:42:00-03:00
-- |       Driver: local
-- |       Name: 3102a6d0af6697012b55dcbbf935d0d6f5888c6ed886a0c2c61016af480a871d
-- |       Mountpoint: /var/lib/docker/volumes/3102a6d0af4697012b55dcbbf935d0d6f0888c6ed889a0c2c61016af480a871d/_data
-- |     
-- |       Scope: local
-- |       CreatedAt: 2020-11-07T10:25:53-03:00
-- |       Driver: local
-- |       Name: 41a0f68c93d267a8546930b7ecb00179373b25423f3c8ae6e4f5fb05207bb75f
-- |       Mountpoint: /var/lib/docker/volumes/4ba0f68c93d267a8586930b7ecb00179373b25426f3c8ae7e4f5fb05207bb75f/_data
-- |     
-- |       Scope: local
-- |       CreatedAt: 2020-11-07T10:25:53-03:00
-- |       Driver: local
-- |       Name: 5fef582298433627aa55fff01c87549ed59a52e4701fdf05885ff0236ffa63ca
-- |       Mountpoint: /var/lib/docker/volumes/5fef582298433667aa56fff01c87549cd59a52e4701fdf05882ff0236ffa63ca/_data
-- |     
-- |       Scope: local
-- |       CreatedAt: 2020-11-04T03:59:55-03:00
-- |       Driver: local
-- |       Name: b37377945f415ae60b5289b41c895b55c6181e531dde5e9967c36c11997a96fd
-- |       Mountpoint: /var/lib/docker/volumes/b37377948f414ae60b5289b41c895b55c6181e031dde4e9967c36c11997a96fd/_data
-- |_  Plugins: 

author = "J. Igor Melo <jigordev@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}

portrule = shortport.version_port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

-- extract all items from the table
extract = function(t, result, name)
	for k, v in pairs(t) do
		k = name and string.format("%s-%s", name, k) or k
		if type(v) ~= "table" then
			if	v ~= "" then
				table.insert(result, string.format("%s: %s", k, v))
			end
		else
			extract(v, result, k)
		end
	end
end

-- request the API and return a json object
perform_request = function(host, port, endpoint)
	local response = http.get(host, port, endpoint)
	if not response or not response.status or response.status ~= 200 or not response.body then
		stdnse.debug1("Failde to retrieve: %s", path)
		return
	end

	local ok_json, json_data = json.parse(response.body)
	
	if ok_json then
		return json_data
	end
	return
end

-- recovers the docker version
get_version = function(host, port)
	local endpoint = "/info"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		return json_data["Version"]
	end
	return
end
	
-- retrieves information about all containers
get_containers = function(host, port)
	local endpoint = "/containers/json?all=1"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		local containers = {}
		for _, items in pairs(json_data) do
			local container = {}
			extract(items, container)
			table.insert(containers, container)
		end
		return containers
	end
	return
end

-- retrieves information about all images
get_images = function(host, port)
	local endpoint = "/images/json"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		local images = {}
		for _, items in pairs(json_data) do
			local image = {}
			extract(items, image)
			table.insert(images, image)
		end
		return images
	end
	return
end

-- retrieves information about all networks
get_networks = function(host, port)
	local endpoint = "/networks"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		local networks = {}
		for _, items in pairs(json_data) do
			local network = {}
			extract(items, network)
			table.insert(networks, network)
		end
		return networks
	end
	return
end

-- retrieves information about all volumes
get_volumes = function(host, port)
	local endpoint = "/volumes"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		local volumes = {}
		for _, items in pairs(json_data["Volumes"]) do
			local volume = {}
			extract(items, volume)
			table.insert(volumes, volume)
		end
		return volumes
	end
	return
end

-- retrieves information about all plugins
get_plugins = function(host, port)
	local endpoint = "/plugins"
	local json_data = perform_request(host, port, endpoint)

	if json_data then
		local plugins = {}
		for _, items in pairs(json_data) do
			local plugin = {}
			extract(items, plugin)
			table.insert(plugins, plugin)
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
