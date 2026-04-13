local srvloc = require "srvloc"
local table = require "table"

description = [[
Discovers Versant object databases using the broadcast srvloc protocol.
]]

---
-- @usage
-- kmap --script broadcast-versant-locate
--
-- @output
-- Pre-scan script results:
-- | broadcast-versant-locate:
-- |_  vod://192.168.200.222:5019
--
-- @xmloutput
-- <table>
--   <elem>vod://192.168.200.222:5019</elem>
-- </table>


author = "Patrik Karlsson"
license = "Same as Kmap--See https://github.com/YurilLAB/Kmap/blob/master/LICENSE"
categories = {"broadcast", "safe"}


prerule = function() return true end

action = function()
  local helper = srvloc.Helper:new()
  local status, result = helper:ServiceRequest("service:odbms.versant:vod", "default")
  helper:close()

  if ( not(status) ) then return end
  local output = {}
  for _, v in ipairs(result) do
    table.insert(output, v:match("^service:odbms.versant:vod://(.*)$"))
  end
  return output
end
