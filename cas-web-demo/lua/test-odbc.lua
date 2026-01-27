local driver = require "luasql.odbc"
local sys = require("system")
sys.setconsoleoutputcp(sys.CODEPAGE_UTF8)

local env = driver.odbc()
local sourcename = 'Kingbase_local'
local conn = env:connect(sourcename)

conn:setautocommit(true)
local cursor = conn:execute("SELECT version()")
local row = cursor:fetch({}, "a")
local colnames = cursor:getcolnames()
for _, colname in ipairs(colnames) do
    print(colname)
end
print(row.VERSION)

cursor:close()
conn:close()
env:close()
