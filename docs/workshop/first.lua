local default_settings = {
   aerospike_port           = 3000,
}


local aerospike_proto = Proto("AerospikeProtocol", "Aerospike Protocol")

function aerospike_proto.dissector(tvbuf, pktinfo, root)
   local pktlen = tvbuf:len()

   pktinfo.cols.protocol:set("Aerospike")

   return pktlen
end

local function enable_dissector()
   DissectorTable.get("tcp.port"):add(default_settings.aerospike_port, aerospike_proto)
end

enable_dissector()
