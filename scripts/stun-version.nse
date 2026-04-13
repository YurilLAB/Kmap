local kmap = require "kmap"
local shortport = require "shortport"
local stun = require "stun"
local stdnse = require "stdnse"

description = [[
Sends a binding request to the server and attempts to extract version
information from the response, if the server attribute is present.
]]

---
-- @usage
-- kmap -sU -sV -p 3478 <target>
-- @output
-- PORT     STATE SERVICE VERSION
-- 3478/udp open  stun    Vovida.org 0.96
--

author = "Patrik Karlsson"
license = "Same as Kmap--See https://kmap.org/book/man-legal.html"
categories = {"version"}


portrule = shortport.version_port_or_service(3478, "stun", "udp")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  local helper = stun.Helper:new(host, port)
  local status = helper:connect()
  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, result = helper:getVersion()
  if ( not(status) ) then
    return fail("Failed to retrieve external IP")
  end

  port.version.name = "stun"
  port.version.product = result
  kmap.set_port_state(host, port, "open")
  kmap.set_port_version(host, port)
end
