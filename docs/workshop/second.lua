local default_settings = {
   aerospike_port           = 3000,
}

local TYPES_PROTO = {
   [1] = "Info",
}

local aerospike_proto = Proto("AerospikeProtocol", "Aerospike Protocol")

-- Constants

local PROTO_VERSION_START  = 0
local PROTO_VERSION_LENGTH = 1

local PROTO_TYPE_START  = 1
local PROTO_TYPE_LENGTH = 1

local INFO_SIZE_START  = 2
local INFO_SIZE_LENGTH = 6
local INFO_DATA_START  = 8

local aerospike_info_proto      = Proto("Aerospike", "Aerospike Info Protocol")

local header_fields = {
   version  = ProtoField.uint8  ("header.version", "Version", base.DEC),
   type     = ProtoField.uint8  ("header.type",    "Type",    base.DEC, TYPES_PROTO),
   size     = ProtoField.uint64 ("header.size",    "Size",    base.DEC),
}

aerospike_info_proto.fields      = header_fields

function aerospike_proto.dissector(tvbuf, pktinfo, root)
   local pktlen = tvbuf:len()

   pktinfo.cols.protocol:set("Aerospike")

   -- Dissect the version field 
   local header_version_tvbr = tvbuf:range(PROTO_VERSION_START, PROTO_VERSION_LENGTH)

   local tree = root:add(aerospike_info_proto, tvbuf:range(0, pktlen))
   tree:add(header_fields.version, header_version_tvbr)
   
   return pktlen
end

local function enable_dissector()
   DissectorTable.get("tcp.port"):add(default_settings.aerospike_port, aerospike_proto)
end

enable_dissector()
