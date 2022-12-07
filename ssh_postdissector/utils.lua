m = {}

function m.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
function m.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end
function m.hexdecode(hex)
    return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end


return m;