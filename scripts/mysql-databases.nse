local mysql = require "mysql"
local kmap = require "kmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local openssl = stdnse.silent_require "openssl"

description = [[
Attempts to list all databases on a MySQL server.
]]

---
-- @args mysqluser The username to use for authentication. If unset it
-- attempts to use credentials found by <code>mysql-brute</code> or
-- <code>mysql-empty-password</code>.
-- @args mysqlpass The password to use for authentication. If unset it
-- attempts to use credentials found by <code>mysql-brute</code> or
-- <code>mysql-empty-password</code>.
--
-- @output
-- 3306/tcp open  mysql
-- | mysql-databases:
-- |   information_schema
-- |   mysql
-- |   horde
-- |   album
-- |   mediatomb
-- |_  squeezecenter

author = "Patrik Karlsson"
license = "Same as Kmap--See https://github.com/YurilLAB/Kmap/blob/master/LICENSE"
categories = {"discovery", "intrusive"}


dependencies = {"mysql-brute", "mysql-empty-password"}

-- Version 0.1
-- Created 01/23/2010 - v0.1 - created by Patrik Karlsson

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

  local socket = kmap.new_socket()
  local catch = function() socket:close() end
  local try = kmap.new_try(catch)
  local result, response, dbs = {}, nil, {}
  local users = {}
  local kmap_args = kmap.registry.args
  local status, rows

  -- set a reasonable timeout value
  socket:set_timeout(5000)

  -- first, let's see if the script has any credentials as arguments?
  if kmap_args.mysqluser then
    users[kmap_args.mysqluser] = kmap_args.mysqlpass or ""
  -- next, let's see if mysql-brute or mysql-empty-password brought us anything
  elseif kmap.registry.mysqlusers then
    -- do we have root credentials?
    if kmap.registry.mysqlusers['root'] then
      users['root'] = kmap.registry.mysqlusers['root']
    else
      -- we didn't have root, so let's make sure we loop over them all
      users = kmap.registry.mysqlusers
    end
  -- last, no dice, we don't have any credentials at all
  else
    stdnse.debug1("No credentials supplied, aborting ...")
    return
  end

  --
  -- Iterates over credentials, breaks once it successfully receives results
  --
  for username, password in pairs(users) do

    try( socket:connect(host, port) )

    response = try( mysql.receiveGreeting( socket ) )
    status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )

    if status and response.errorcode == 0 then
      local status, rs = mysql.sqlQuery( socket, "show databases" )
      if status then
        result = mysql.formatResultset(rs, { noheaders = true })

        -- if we got here as root, we've got them all
        -- if we're here as someone else, we cant be sure
        if username == 'root' then
          break
        end
      end
    end
    socket:close()
  end
  return stdnse.format_output(true, result)
end
