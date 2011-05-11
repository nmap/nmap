description = [[
Tries to give a list of installed WordPress plugins.

The script will brute force the /wp-content/plugins/ folder with a dictionnary
of 14K (and counting) known WP plugins. Anything but a 404 means that a given
plugin directory probably exists, so the plugin probably also does.

The available plugins for Wordpress is huge and despite the efforts of Nmap to
parallelize the queries, a whole search could take an hour or so. That's why
the plugin list is sorted by popularity and by default the script will only
check the first 100 ones. Users can tweak this with an option (see below).
]]

---
-- @args http-wp-plugins.root If set, points to the blog root directory on the website. If not, the script will try to find a WP directory installation or fall back to root.
-- @args http-wp-plugins.search As the plugins list contains tens of thousand of plugins, this script will only search the 100 most popular ones by default.
-- Use this option with a number or "all" as an argument for a more comprehensive brute force.
--
-- @usage
-- nmap --script=http-wp-plugins --script-arg http-wp-plugins.root="/blog/",http-wp-plugins.search=500 <targets>
--
--@output
-- Interesting ports on my.woot.blog (123.123.123.123):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-wp-plugins:
-- | search amongst the 500 most popular plugins
-- |   akismet
-- |   wp-db-backup
-- |   all-in-one-seo-pack
-- |   stats
-- |_  wp-to-twitter

author = "Ange Gutek <ange.gutek@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

require 'http'
require 'stdnse'
require 'shortport'

local DEFAULT_PLUGINS_SEARCH = 100


portrule = shortport.service("http")


action = function(host, port)

  local result = {}
  local all = {}
  local bfqueries = {}

  --Check if the wp plugins list exists
  local wp_plugins_file = nmap.fetchfile("nselib/data/wp-plugins.lst")
  if not wp_plugins_file then
    return false, "Couldn't find wp-plugins.lst (should be in nselib/data)"
  end

  local file = io.open(wp_plugins_file, "r")
  if not file then
    return false, "Couldn't find wp-plugins.lst (should be in nselib/data)"
  end

  local wp_autoroot
  local wp_root = stdnse.get_script_args("http-wp-plugins.root")
  local plugins_search = DEFAULT_PLUGINS_SEARCH
  local plugins_search_arg = stdnse.get_script_args("http-wp-plugins.search")

  if plugins_search_arg == "all" then
    plugins_search = nil
  elseif plugins_search_arg then
    plugins_search = tonumber(plugins_search_arg)
  end

  stdnse.print_debug(1, "%s plugins search range: %s", SCRIPT_NAME, plugins_search or "unlimited")


  -- search the website root for evidences of a Wordpress path
  if not wp_root then
    local target_index = http.get(host,port, "/")

    if target_index.status and target_index.body then
      wp_autoroot = string.match(target_index.body, "http://[%w%-%.]-/([%w%-%./]-)wp%-content")
      if wp_autoroot then
        wp_autoroot = "/" .. wp_autoroot
        stdnse.print_debug(1, "%s WP root directory: %s", SCRIPT_NAME, wp_autoroot)
      else
        stdnse.print_debug(1, "%s WP root directory: wp_autoroot was unable to find a WP content dir (root page returns %d).", SCRIPT_NAME, target_index.status)
      end
    end
  end


  --identify the 404
  local status_404, result_404, body_404 = http.identify_404(host, port)
  if not status_404 then
    stdnse.print_debug(1, "%s unable to handle 404 pages (%s)", SCRIPT_NAME, result_404)
  end


  --build a table of both directories to brute force and the corresponding WP plugins' name
  local plugin_count = 0
  while true do
    local line = file:read()
    if not line then
      break
    end

    if plugins_search and plugin_count >= plugins_search then
      break
    end

    local target
    if wp_root then
      -- Give user-supplied argument the priority
      target = wp_root .. "/wp-content/plugins/" .. line .. "/"
    elseif wp_autoroot then
      -- Maybe the script has discovered another Wordpress content directory
      target = wp_autoroot .. "wp-content/plugins/" .. line .. "/"
    else
      -- Default WP directory is root
      target = "/wp-content/plugins/" .. line .. "/"
    end


    target = string.gsub(target, "//", "/")
    table.insert(bfqueries, {target, line})
    all = http.pipeline_add(target, nil, all, "GET")
    plugin_count = plugin_count + 1

  end

  -- release hell...
  local pipeline_returns = http.pipeline_go(host, port, all)
  if not pipeline_returns then
    stdnse.print_debug(1, "%s : got no answers from pipelined queries", SCRIPT_NAME)
  end

  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the plugin is present
    if http.page_exists(data, result_404, body_404, bfqueries[i][1], true) then
      stdnse.print_debug(1, "http-wp-plugins.nse: Found a plugin: %s", bfqueries[i][2])
      table.insert(result, bfqueries[i][2])
    end
  end


  if #result > 0 then
    result.name = "search amongst the " .. plugin_count .. " most popular plugins"
    return stdnse.format_output(true, result)
  else
    return "nothing found amongst the " .. plugin_count .. " most popular plugins, use --script-arg http-wp-plugins.search=<number|all> for deeper analysis)\n"
  end

end

