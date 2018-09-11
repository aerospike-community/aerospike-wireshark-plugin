-- aerospike.lua: Aerospike Wireshark Lua plugin

-- Copyright (c) 2008-2018 Aerospike, Inc.

-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.

-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Run with: wireshark -X lua_script:aerospike.lua capture.pcapng

-- # Requires

_G.debug     = require("debug")
local luacov = require("luacov")

-- # Configuration

local default_settings = {
   aerospike_port           = 3000,
   heartbeat_multicast_port = 9918,
   heartbeat_mesh_port      = 3002,
}

-- ## Common

local TYPES_PROTO = {
   [1] = "Info",
   [3] = "Message",
}

local aerospike_proto      = Proto("AerospikeProtocol",               "Aerospike Protocol")

local PACKET_REQUEST  = 1
local PACKET_RESPONSE = 2

-- # Helper Functions

-- https://stackoverflow.com/a/7615129/7651396
local function mysplit(inputstr, sep)
   if sep == nil then
      sep = "%s"
   end
   local t={}
   local i=1
   for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
      t[i] = str
      i = i + 1
   end
   return t
end

local function split_tab(str)
   return mysplit(str, '\t')
end

-- https://stackoverflow.com/a/15706820
function spairs(t, order)
    -- collect the keys
    local keys = {}
    for k in pairs(t) do keys[#keys+1] = k end

    -- if order function given, sort by it by passing the table and keys a, b,
    -- otherwise just sort the keys
    if order then
        table.sort(keys, function(a,b) return order(t, a, b) end)
    else
        table.sort(keys)
    end

    -- return the iterator function
    local i = 0
    return function()
        i = i + 1
        if keys[i] then
            return keys[i], t[keys[i]]
        end
    end
end

-- # Statistics

-- ## Hot Key

local hotkeys = {}

local function debug_hotkeys()
   for k,v in pairs(hotkeys) do
      print(k, v[1], v[2], v[3])
   end
end

local function update_hotkeys(key, packet_type)
   if hotkeys[key] then
      hotkeys[key][packet_type] = hotkeys[key][packet_type] + 1
   else
      hotkeys[key] = {}
      hotkeys[key][PACKET_REQUEST]  = 0
      hotkeys[key][PACKET_RESPONSE] = 0
      hotkeys[key][packet_type]     = 1
   end
end

-- Update delta
local function calculate_delta()
   for k,v in pairs(hotkeys) do
      -- Delta = Request - Response
      v[3] = v[1] - v[2]
   end
end

-- # GUI

if gui_enabled() then
   instances = 0

   local function menuable_tap()
      instances = instances + 1

      local td = {}
      td.win = TextWindow.new("Hot Key Report " .. instances)
      td.text = ""
      td.instance = instances

      local tap = Listener.new();

      function remove_tap()
         if tap and tap.remove then
            tap:remove();
         end
      end

      td.win:set_atclose(remove_tap)

      function tap.draw(t)
         td.win:clear()

         calculate_delta()

         td.win:append("Hot Key Report\n\n")
         td.win:append("Key                                      Request\tResponse\tδ\n")
         for k,v in spairs(hotkeys, function(t, a, b) return t[b][3] < t[a][3] end) do
              td.win:append(k .. "\t" .. tostring(v[1]) .. "\t" .. tostring(v[2]) .. "\t" .. tostring(v[3]) .. "\n");
          end
      end

      function tap.reset()
         td.win:clear()
         hotkeys = {}
      end
   end

   register_menu("Aerospike/Hot Key Report",menuable_tap,MENU_STAT_UNSORTED)
end

-- # Protocols

-- ## Info

-- Aerospike Info Protocol

-- >   +------------------------------+-------------+
-- >   |  Aerospike Protocol Header   |   Message   |
-- >   +------------------------------+-------------+

-- >   +---------+----------+-------------------------+
-- >   | version |   type   |         size            |
-- >   +---------+----------+-------------------------+
-- >   0         1          2                         8

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

-- Constants

local PROTO_VERSION_START  = 0
local PROTO_VERSION_LENGTH = 1

local PROTO_HEADER_START  = 1
local PROTO_HEADER_LENGTH = 1

local PROTO_TYPE_INFO = 1
local PROTO_TYPE_MSG  = 3

local INFO_SIZE_START  = 2
local INFO_SIZE_LENGTH = 6
local INFO_DATA_START  = 8

-- Create Proto objects

local aerospike_info_proto      = Proto("Aerospike",               "Aerospike Info Protocol")
local aerospike_attribute       = Proto("AerospikeAttribute",      "Aerospike Attributes")
local aerospike_attribute_value = Proto("AerospikeAttributeValue", "Aerospike Attribute Value pairs")

-- Proto header fields

local header_fields = {
   version  = ProtoField.uint8  ("header.version", "Version", base.DEC),
   type     = ProtoField.uint8  ("header.type",    "Type",    base.DEC, TYPES_PROTO),
   size     = ProtoField.uint64 ("header.size",    "Size",    base.DEC),
}

local header_attributes = {
   attribute = ProtoField.string("header.attribute", "Attribute"),
}

local header_attribute_values = {
   attribute = ProtoField.string("header_attribute_values.attribute",   "Attribute "),
   value     = ProtoField.string("header_attribute_values.value",       "Value"),
}

-- Register the protocol fields

aerospike_info_proto.fields      = header_fields
aerospike_attribute.fields       = header_attributes
aerospike_attribute_value.fields = header_attribute_values

-- Functions

local function dissect_aerospike_info (tvbuf, tree, size)
   -- Separate the data by newline
   local data_tvbr = tvbuf:range(INFO_DATA_START, tonumber(size))
   local data_string = data_tvbr:string()

   -- local subtree = tree:add(aerospike_attribute, data_tvbr)
   local data_start = INFO_DATA_START
   for line in string.gmatch(data_string, "[^\n]+") do
      local d = tvbuf:range(data_start, string.len(line))
      local d_string = d:string()

      -- if contains attribute-values
      if string.find(d_string, "\t") then
         local parts = split_tab(d_string)

         local string_start = data_start
         for p, q in pairs(parts) do                                    -- p  q
            local value = tvbuf:range(string_start, string.len(q))      -- 1  node
            if math.fmod(p, 2) > 0 then                  -- Attribute   -- 2  BB9B11300000000
               tree:add(header_attribute_values.attribute, value)       -- 1  peers-generation
            else                                         -- Value       -- 2  1
               tree:add(header_attribute_values.value, value)           -- 1  partition-generation
            end                                                         -- 2  0
            string_start = string_start + string.len(q) + 1 -- for \t
         end
      else
         tree:add(header_attributes.attribute, d)
      end
      data_start = data_start + string.len(line) + 1 -- for \n
  end
end


-- ## Batch

-- Batch Request

-- >   +--------+--------+----------+----------+----------+
-- >   |  Size  | Inline |  Item 1  |  Item 2  |   ...    |
-- >   +--------+--------+----------+----------+----------+
-- >   0        4        5

-- Batch Request Item

-- >   +-------+------------------+-------------+-----------+-------------+------------+-------+
-- >   | Index |      Digest      | Full Header | Read Attr | Field Count | Field Size | Value |
-- >   +-------+------------------+-------------+-----------+-------------+------------+-------+
-- >   0       4                 24            25           26            28           34

-- Constants

local BATCH_SIZE                 =  4
local BATCH_ALLOW_INLINE_SIZE    =  1

local BATCH_INDEX_SIZE           =  4
local BATCH_DIGEST_SIZE          = 20
local BATCH_USE_FULL_HEADER_SIZE =  1
local BATCH_READ_ATTR_SIZE       =  1
local BATCH_FIELD_COUNT          =  2
local BATCH_NUMBER_OF_BINS       =  2
local BATCH_NAMESPACE_SIZE       =  4
local BATCH_BINS_COUNT_SIZE      =  4

-- Create Proto objects

local aerospike_batch_proto      = Proto("AerospikeBatch",     "Aerospike Batch Protocol")
local aerospike_batch_item_proto = Proto("AerospikeBatchItem", "Aerospike Batch Item" )

-- Proto header fields

local batch_fields = {
   size   = ProtoField.uint64 ("batch.size",   "Size",   base.DEC),
   inline = ProtoField.uint8  ("batch.inline", "Inline", base.DEC),
}

local batch_item_fields = {
   index            = ProtoField.uint64 ("batch.index",            "Index",           base.DEC),
   digest           = ProtoField.bytes  ("batch.digest",           "Digest",          base.NONE),
   full_header      = ProtoField.uint8  ("batch.full_header",      "FullHeader",      base.DEC),
   read_attr        = ProtoField.uint8  ("batch.read_attr",        "ReadAttr",        base.DEC),
   field_count      = ProtoField.uint16 ("batch.field_count",      "FieldCount",      base.DEC),
   number_of_bins   = ProtoField.uint16 ("batch.number_of_bins",   "NumberOfBins",    base.DEC),
   namespace_length = ProtoField.uint32 ("batch.namespace_length", "NamespaceLength", base.DEC),
   bins_count       = ProtoField.uint32 ("batch.bins_count",       "BinsCount",       base.DEC),
   value            = ProtoField.bytes  ("batch.value",            "Value",           base.NONE), -- String starts with 00, and hence using bytes
}

-- local batch_item_order = {
--   { BATCH_INDEX_SIZE,           batch_item_fields.index       },
--   { BATCH_DIGEST_SIZE,          batch_item_fields.digest      },
--   { BATCH_USE_FULL_HEADER_SIZE, batch_item_fields.full_header },
--   { BATCH_READ_ATTR_SIZE,       batch_item_fields.read_attr   },
--   { BATCH_FIELD_COUNT,          batch_item_fields.field_count },
-- }

-- Register the protocol fields

aerospike_batch_proto.fields       = batch_fields
aerospike_batch_item_proto.fields  = batch_item_fields

-- ## Message

-- Aerospike Message Protocol

-- >   +-----------------+---------+--------------+
-- >   |  Header Section |  Fields |  Operations  |
-- >   +-----------------+---------+--------------+

-- ### Aerospike Message: Header Section

-- >   +-----------+--------+--------+-------+--------+---------------+-------------+
-- >   | header_sz |  info1 | info2  | info3 | unused |   result_code | generation  |
-- >   +-----------+--------+--------+-------+--------+---------------+-------------+
-- >   8           9        10       11      12       13              14            18
-- >   +------------+-----------------+---------+--------+--------------------------+
-- >   | record_ttl | transaction_ttl | n_fields| n_ops  |  data (proto.sz-22)      |
-- >   +------------+-----------------+---------+--------+--------------------------+
-- >   18           22                26        28       30

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

-- Constants

local MSG_HEADER_SZ_START  = 8
local MSG_HEADER_SZ_LENGTH = 1
local MSG_INFO1_START = 9
local MSG_INFO1_LENGTH = 1
local MSG_INFO2_START = 10
local MSG_INFO2_LENGTH = 1
local MSG_INFO3_START = 11
local MSG_INFO3_LENGTH = 1
local MSG_UNUSED_START = 12
local MSG_UNUSED_LENGTH = 1
local MSG_RESULT_CODE_START = 13
local MSG_RESULT_CODE_LENGTH = 1
local MSG_GENERATION_START = 14
local MSG_GENERATION_LENGTH = 4
local MSG_RECORD_TTL_START = 18
local MSG_RECORD_TTL_LENGTH = 4
local MSG_TRANSACTION_TTL_START = 22
local MSG_TRANSACTION_TTL_LENGTH = 4
local MSG_NFIELDS_START = 26
local MSG_NFIELDS_LENGTH = 2
local MSG_NOPS_START = 28
local MSG_NOPS_LENGTH = 2

local MSG_OPERATIONS_START = 28
local MSG_OPERATIONS_LENGTH = 2

local MSG_HEADER_LENGTH = MSG_HEADER_SZ_LENGTH +
   MSG_INFO1_LENGTH +
   MSG_INFO2_LENGTH +
   MSG_INFO3_LENGTH +
   MSG_UNUSED_LENGTH +
   MSG_RESULT_CODE_LENGTH +
   MSG_GENERATION_LENGTH +
   MSG_RECORD_TTL_LENGTH +
   MSG_TRANSACTION_TTL_LENGTH +
   MSG_NFIELDS_LENGTH +
   MSG_NOPS_LENGTH

local message_header_table = {
   { MSG_HEADER_SZ_START,       MSG_HEADER_SZ_LENGTH,       "header_sz"       },
   { MSG_INFO1_START,           MSG_INFO1_LENGTH,           "info1"           },
   { MSG_INFO2_START,           MSG_INFO2_LENGTH,           "info2"           },
   { MSG_INFO3_START,           MSG_INFO3_LENGTH,           "info3"           },
   { MSG_UNUSED_START,          MSG_UNUSED_LENGTH,          "unused"          },
   { MSG_RESULT_CODE_START,     MSG_RESULT_CODE_LENGTH,     "result_code"     },
   { MSG_GENERATION_START,      MSG_GENERATION_LENGTH,      "generation"      },
   { MSG_RECORD_TTL_START,      MSG_RECORD_TTL_LENGTH,      "record_ttl"      },
   { MSG_TRANSACTION_TTL_START, MSG_TRANSACTION_TTL_LENGTH, "transaction_ttl" },
   { MSG_NFIELDS_START,         MSG_NFIELDS_LENGTH,         "n_fields"        },
   { MSG_NOPS_START,            MSG_NOPS_LENGTH,            "n_ops"           },
}

local info1_order = {
   [1] = "level_b1",
   [2] = "level_b0",
   [3] = "get_no_bins",
   [4] = "xdr",
   [5] = "batch",
   [6] = "unused",
   [7] = "get_all",
   [8] = "read",
}

local info2_order = {
   [1] = "respond_all_ops",
   [2] = "unused",
   [3] = "create_only",
   [4] = "durable_delete",
   [5] = "generation_gt",
   [6] = "generation",
   [7] = "delete",
   [8] = "write",
}

local info3_order = {
   [1] = "unused2",
   [2] = "unused1",
   [3] = "replace_only",
   [4] = "create_or_replace",
   [5] = "update_only",
   [6] = "level_b1",
   [7] = "level_b0",
   [8] = "last",
}

-- Proto header fields

local message_proto_fields = {
   version  = ProtoField.uint8  ("message.version", "Version", base.DEC),
   type     = ProtoField.uint8  ("message.type",    "Type",    base.DEC, TYPES_PROTO),
   size     = ProtoField.uint64 ("message.size",    "Size",    base.DEC),
}

local message_header = {
   header_sz       = ProtoField.uint8  ("message.header_sz",       "Header Size",          base.DEC),
   -- info1, info2 and info3 created using bit fields
   unused          = ProtoField.uint8  ("message.unused",          "Unused",               base.DEC),
   result_code     = ProtoField.uint8  ("message.result_code",     "Result code",          base.DEC),
   generation      = ProtoField.uint32 ("message.generation",      "Generation",           base.DEC),
   record_ttl      = ProtoField.uint32 ("message.record_ttl",      "Record TTL",           base.DEC),
   transaction_ttl = ProtoField.uint32 ("message.transaction_ttl", "Transaction TTL",      base.DEC),
   n_fields        = ProtoField.uint16 ("message.n_fields",        "Number of fields",     base.DEC),
   n_ops           = ProtoField.uint16 ("message.n_ops",           "Number of operations", base.DEC),
}

-- info1

-- | Value |                Name               |                         Description                          |
-- |------:|:----------------------------------|:-------------------------------------------------------------|
-- |    1	| AS_MSG_INFO1_READ	                | Contains a read operation                                    |
-- |    2	| AS_MSG_INFO1_GET_ALL	            | Get all bins' data                                           |
-- |    4	| Unused	                        | Unused                                                       |
-- |    8	| AS_MSG_INFO1_BATCH                | New batch protocol                                           |
-- |   16	| AS_MSG_INFO1_XDR	                | Operation is performed by XDR                                |
-- |   32  | AS_MSG_INFO1_GET_NO_BINS          | Do no read the bin information                               |
-- |   64	| AS_MSG_INFO1_CONSISTENCY_LEVEL_B0 | Read consistency level - bit 0                               |
-- |  128	| AS_MSG_INFO1_CONSISTENCY_LEVEL_B1 | Read consistency level - bit 1                               |

local info1_fields = {
   read        = ProtoField.new ("AS_MSG_INFO1_READ",                 "info1.read",        ftypes.BOOLEAN, {"1", "0"}, 8, 0x01),
   get_all     = ProtoField.new ("AS_MSG_INFO1_GET_ALL",              "info1.get_al",      ftypes.BOOLEAN, {"1", "0"}, 8, 0x02),
   unused      = ProtoField.new ("Unused",                            "info1.unused",      ftypes.BOOLEAN, {"1", "0"}, 8, 0x04),
   batch       = ProtoField.new ("AS_MSG_INFO1_BATCH",                "info1.batch",       ftypes.BOOLEAN, {"1", "0"}, 8, 0x08),
   xdr         = ProtoField.new ("AS_MSG_INFO1_XDR",                  "info1.xdr",         ftypes.BOOLEAN, {"1", "0"}, 8, 0x10),
   get_no_bins = ProtoField.new ("AS_MSG_INFO1_GET_NO_BINS",          "info1.get_no_bins", ftypes.BOOLEAN, {"1", "0"}, 8, 0x20),
   level_b0    = ProtoField.new ("AS_MSG_INFO1_CONSISTENCY_LEVEL_B0", "info1.level_b0",    ftypes.BOOLEAN, {"1", "0"}, 8, 0x40),
   level_b1    = ProtoField.new ("AS_MSG_INFO1_CONSISTENCY_LEVEL_B1", "info1.level_b1",    ftypes.BOOLEAN, {"1", "0"}, 8, 0x80),
}

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

-- info2

-- | Value |                Name               |                               Description                                |
-- |------:|:----------------------------------|:-------------------------------------------------------------------------|
-- |    1  | AS_MSG_INFO2_WRITE                | Contains a write operation                                               |
-- |    2	| AS_MSG_INFO2_DELETE               | Delete record                                                            |
-- |    4	| AS_MSG_INFO2_GENERATION	        | Pay attention to the generation                                          |
-- |    8	| AS_MSG_INFO2_GENERATION_GT	    | Apply write if new generation >= old, good for restore                   |
-- |   16  | AS_MSG_INFO2_DURABLE_DELETE	    | Operation resulting in record deletion leaves tombstone                  |
-- |   32	| AS_MSG_INFO2_CREATE_ONLY          | Write record only if it doesn't exist                                    |
-- |   64	| Unused                            | Reserved                                                                 |
-- |  128	| AS_MSG_INFO2_RESPOND_ALL_OPS      | All bin ops (read, write or modify) require a response, in request order |

local info2_fields = {
   write           = ProtoField.new ("AS_MSG_INFO2_WRITE",           "info2.write",           ftypes.BOOLEAN, {"1", "0"}, 8, 0x01),
   delete          = ProtoField.new ("AS_MSG_INFO2_DELETE",          "info2.delete",          ftypes.BOOLEAN, {"1", "0"}, 8, 0x02),
   generation      = ProtoField.new ("AS_MSG_INFO2_GENERATION",      "info2.generation",      ftypes.BOOLEAN, {"1", "0"}, 8, 0x04),
   generation_gt   = ProtoField.new ("AS_MSG_INFO2_GENERATION_GT",   "info2.generation_dt",   ftypes.BOOLEAN, {"1", "0"}, 8, 0x08),
   durable_delete  = ProtoField.new ("AS_MSG_INFO2_DURABLE_DELETE",  "info2.durable_delete",  ftypes.BOOLEAN, {"1", "0"}, 8, 0x10),
   create_only     = ProtoField.new ("AS_MSG_INFO2_CREATE_ONLY",     "info2.create_only",     ftypes.BOOLEAN, {"1", "0"}, 8, 0x20),
   unused          = ProtoField.new ("Unused",                       "info2.unused",          ftypes.BOOLEAN, {"1", "0"}, 8, 0x40),
   respond_all_ops = ProtoField.new ("AS_MSG_INFO2_RESPOND_ALL_OPS", "info2.respond_all_ops", ftypes.BOOLEAN, {"1", "0"}, 8, 0x80),
}

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

-- info3

-- | Value |              Name              |                         Description                          |
-- |------:|:-------------------------------|:-------------------------------------------------------------|
-- |    1	| AS_MSG_INFO3_LAST	             | This is the last part of a multi-part message                |
-- |    2	| AS_MSG_INFO3_COMMIT_LEVEL_B0   | Write commit level - bit 0                                   |
-- |    4  | AS_MSG_INFO3_COMMIT_LEVEL_B1   | Write commit level - bit 1                                   |
-- |    8	| AS_MSG_INFO3_UPDATE_ONLY       | Update existing record only, do not create new record        |
-- |   16	| AS_MSG_INFO3_CREATE_OR_REPLACE | Completely replace existing record, or create new record     |
-- |   32	| AS_MSG_INFO3_REPLACE_ONLY      | Completely replace existing record, do not create new record |
-- |   64	| Unused                         | Reserved                                                     |
-- |  128  | Unused                         | Reserved                                                     |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

local info3_fields = {
   last              = ProtoField.new ("AS_MSG_INFO3_LAST",              "info3.last",              ftypes.BOOLEAN, {"1", "0"}, 8, 0x01),
   level_b0          = ProtoField.new ("AS_MSG_INFO3_COMMIT_LEVEL_B0",   "info3.level_b0",          ftypes.BOOLEAN, {"1", "0"}, 8, 0x02),
   level_b1          = ProtoField.new ("AS_MSG_INFO3_COMMIT_LEVEL_B1",   "info3.level_b1",          ftypes.BOOLEAN, {"1", "0"}, 8, 0x04),
   update_only       = ProtoField.new ("AS_MSG_INFO3_UPDATE_ONLY",       "info3.update_only",       ftypes.BOOLEAN, {"1", "0"}, 8, 0x08),
   create_or_replace = ProtoField.new ("AS_MSG_INFO3_CREATE_OR_REPLACE", "info3.create_or_replace", ftypes.BOOLEAN, {"1", "0"}, 8, 0x10),
   replace_only      = ProtoField.new ("AS_MSG_INFO3_REPLACE_ONLY",      "info3.replace_only",      ftypes.BOOLEAN, {"1", "0"}, 8, 0x20),
   unused1           = ProtoField.new ("AS_MSG_INFO3_UNUSED1",           "info3.unused1",           ftypes.BOOLEAN, {"1", "0"}, 8, 0x40),
   unused2           = ProtoField.new ("AS_MSG_INFO3_UNUSED2",           "info3.unused1",           ftypes.BOOLEAN, {"1", "0"}, 8, 0x80),
}

-- Create Proto objects

local aerospike_msg_proto       = Proto("AerospikeMessage"      , "Aerospike Message Protocol")
local aerospike_msg_header      = Proto("AerospikeMessageHeader", "Aerospike Message Header")
local aerospike_info1           = Proto("AerospikeInfo1",         "Info1")
local aerospike_info2           = Proto("AerospikeInfo2",         "Info2")
local aerospike_info3           = Proto("AerospikeInfo3",         "Info3")

local info_selection = {
   [MSG_INFO1_START] = {aerospike_info1, info1_fields, info1_order },
   [MSG_INFO2_START] = {aerospike_info2, info2_fields, info2_order },
   [MSG_INFO3_START] = {aerospike_info3, info3_fields, info3_order },
}

-- Register the protocol fields

aerospike_msg_proto.fields      = message_proto_fields
aerospike_msg_header.fields     = message_header
aerospike_info1.fields          = info1_fields
aerospike_info2.fields          = info2_fields
aerospike_info3.fields          = info3_fields

-- ### Aerospike Message: Fields

-- >   +------------+------------+----------------------+
-- >   |   size     | field_type |    data (size-1)     |
-- >   +------------+------------+----------------------+
-- >   30           34           35

-- Constants

local MSG_FIELDS_VALUES_START = 30
local MSG_FIELDS_VALUES_SIZE_LENGTH = 4

-- Field Types

-- | Value |                Name                 |   Type   |                        Description                   |
-- |------:|:------------------------------------|:---------|:-----------------------------------------------------|
-- |   0	| AS_MSG_FIELD_TYPE_NAMESPACE         | String   | Namespace	                                        |
-- |   1	| AS_MSG_FIELD_TYPE_SET	              | String   | A particular set within the namespace	            |
-- |   2	| AS_MSG_FIELD_TYPE_KEY	              | Bytes    | The key	                                            |
-- |   3	| AS_MSG_FIELD_TYPE_BIN               | String   | Unused	                                            |
-- |   4	| AS_MSG_FIELD_TYPE_DIGEST_RIPE       | Bytes    | The RIPEMD160 digest representing the key (20 bytes)	|
-- |   5	| AS_MSG_FIELD_TYPE_GU_TID	          | String   | Unused	                                            |
-- |   6	| AS_MSG_FIELD_TYPE_DIGEST_RIPE_ARRAY | Bytes    | An array of digests	                                |
-- |   7	| AS_MSG_FIELD_TYPE_TRID              |	Integer	 | Transaction ID	                                    |
-- |   8	| AS_MSG_FIELD_TYPE_SCAN_OPTIONS	  | Bytes	 | Scan operation options	                            |
-- |   9	| AS_MSG_FIELD_TYPE_SOCKET_TIMEOUT	  | Integer	 | Socket timeout                                       |
-- |  21	| AS_MSG_FIELD_TYPE_INDEX_NAME        |	String   | Secondary index name	                                |
-- |  22	| AS_MSG_FIELD_TYPE_INDEX_RANGE	      | Bytes    | Secondary index query range	                        |
-- |  26   | AS_MSG_FIELD_TYPE_INDEX_TYPE        |	Integer  | Secondary index type (as_sindex_type enum)	        |
-- |  30   | AS_MSG_FIELD_TYPE_UDF_FILENAME      |	String   | UDF filename	                                        |
-- |  31	| AS_MSG_FIELD_TYPE_UDF_FUNCTION	  | String   | UDF function	                                        |
-- |  32	| AS_MSG_FIELD_TYPE_UDF_ARGLIST	      | Bytes    | UDF argument list (as_val)	                        |
-- |  33	| AS_MSG_FIELD_TYPE_UDF_OP            |	Integer  | UDF operation type (as_udf_op enum)	                |
-- |  40   | AS_MSG_FIELD_TYPE_QUERY_BINLIST     |	Bytes    | Bins to return on a secondary index query	        |
-- |  41   | AS_MSG_FIELD_TYPE_BATCH             |	Bytes	 | Batch                                                |
-- |  42	| AS_MSG_FIELD_TYPE_BATCH_WITH_SET	  | Bytes    | Batch with set	                                    |
-- |  43	| AS_MSG_FIELD_TYPE_PREDEXP	          | Bytes    | Predicate expression                                 |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

local TYPES_MSG_FIELDS = {
     [0] = "AS_MSG_FIELD_TYPE_NAMESPACE",
     [1] = "AS_MSG_FIELD_TYPE_SET",
     [2] = "AS_MSG_FIELD_TYPE_KEY",
     [3] = "AS_MSG_FIELD_TYPE_BIN",
     [4] = "AS_MSG_FIELD_TYPE_DIGEST_RIPE",
     [5] = "AS_MSG_FIELD_TYPE_GU_TID",
     [6] = "AS_MSG_FIELD_TYPE_DIGEST_RIPE_ARRAY",
     [7] = "AS_MSG_FIELD_TYPE_TRID",
     [8] = "AS_MSG_FIELD_TYPE_SCAN_OPTIONS",
     [9] = "AS_MSG_FIELD_TYPE_SOCKET_TIMEOUT",
    [21] = "AS_MSG_FIELD_TYPE_INDEX_NAME",
    [22] = "AS_MSG_FIELD_TYPE_INDEX_RANGE",
    [26] = "AS_MSG_FIELD_TYPE_INDEX_TYPE",
    [30] = "AS_MSG_FIELD_TYPE_UDF_FILENAME",
    [31] = "AS_MSG_FIELD_TYPE_UDF_FUNCTION",
    [32] = "AS_MSG_FIELD_TYPE_UDF_ARGLIST",
    [33] = "AS_MSG_FIELD_TYPE_UDF_OP",
    [40] = "AS_MSG_FIELD_TYPE_QUERY_BINLIST",
    [41] = "AS_MSG_FIELD_TYPE_BATCH",
    [42] = "AS_MSG_FIELD_TYPE_BATCH_WITH_SET",
    [43] = "AS_MSG_FIELD_TYPE_PREDEXP",
}

-- Proto header fields

local message_fields = {
   size         = ProtoField.uint32 ("message.size",        "Size",         base.DEC),
   field_type   = ProtoField.uint8  ("message.type",        "Field Type",   base.DEC,  TYPES_MSG_FIELDS),
   data_str     = ProtoField.string ("message.data_str",    "Data string"),
   data_int     = ProtoField.uint64 ("message.data_int",    "Data integer", base.DEC),
   data_double  = ProtoField.double ("message.data_double", "Data float",   base.DEC),
   data_bytes   = ProtoField.bytes  ("message.bytes",       "Data bytes",   base.NONE),
}

local TYPES_MSG_FIELDS_DATA_TYPE = {
     [0] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_NAMESPACE
     [1] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_SET
     [2] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_KEY
     [3] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_BIN
     [4] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_DIGEST_RIPE
     [5] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_GU_TID
     [6] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_DIGEST_RIPE_ARRAY
     [7] = message_fields.data_int,   -- AS_MSG_FIELD_TYPE_TRID
     [8] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_SCAN_OPTIONS
     [9] = message_fields.data_int,   -- AS_MSG_FIELD_TYPE_SOCKET_TIMEOUT
    [21] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_INDEX_NAME
    [22] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_INDEX_RANGE
    [26] = message_fields.data_int,   -- AS_MSG_FIELD_TYPE_INDEX_TYPE
    [30] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_UDF_FILENAME
    [31] = message_fields.data_str,   -- AS_MSG_FIELD_TYPE_UDF_FUNCTION
    [32] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_UDF_ARGLIST
    [33] = message_fields.data_int,   -- AS_MSG_FIELD_TYPE_UDF_OP
    [40] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_QUERY_BINLIST
    [41] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_BATCH
    [42] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_BATCH_WITH_SET
    [43] = message_fields.data_bytes, -- AS_MSG_FIELD_TYPE_PREDEXP
}

-- Create a Proto object

local aerospike_msg_fields      = Proto("AerospikeFields",         "Aerospike Fields")

-- Register the protocol fields

aerospike_msg_fields.fields      = message_fields

-- ### Aerospike Message: Operations

-- >   +------+----+---------------+-------------+-----------------+----------+-----------------+
-- >   | size | op | bin data type | bin version | bin name length | bin name |       data      |
-- >   +------+----+---------------+-------------+-----------------+----------+-----------------+
-- >      4     1         1               1               1               N      size - (N + 4)

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

-- Constants

local MSG_OPERATIONS_VALUES_SIZE_LENGTH = 4
local MSG_OPERATIONS_VALUES_OP_LENGTH = 1
local MSG_OPERATIONS_VALUES_BIN_DATA_TYPE_LENGTH = 1
local MSG_OPERATIONS_VALUES_BIN_VERSION_LENGTH = 1
local MSG_OPERATIONS_VALUES_BIN_NAME_LENGTH = 1

-- Op

-- | Value |        Name          |                         Description                        |
-- |------:|:---------------------|:-----------------------------------------------------------|
-- |    1	| AS_MSG_OP_READ       | Read the value                                             |
-- |    2	| AS_MSG_OP_WRITE      | Write the value                                            |
-- |    3	| AS_MSG_OP_CDT_READ   | Prospective CDT top-level ops                              |
-- |    4	| AS_MSG_OP_CDT_MODIFY | Prospective CDT top-level ops                              |
-- |    5	| AS_MSG_OP_INCR       | Add a value to an existing value (only on integers)        |
-- |    6	| Unused               | Reserved                                                   |
-- |    7	| Unused               | Reserved                                                   |
-- |    8	| Unused               | Reserved                                                   |
-- |    9	| AS_MSG_OP_APPEND     | Append a value to an existing value (on strings and blobs) |
-- |   10	| AS_MSG_OP_PREPEND    | Prepend a value to an existing value (on strings a blobs)  |
-- |   11	| AS_MSG_OP_TOUCH      | Touch a value (will only increment the generation)         |
-- |  129	| AS_MSG_OP_MC_INCR	   | Memcache-compatible version of the increment command       |
-- |  130	| AS_MSG_OP_MC_APPEND  | Append value to existing value (only on strings)           |
-- |  131	| AS_MSG_OP_MC_PREPEND | Prepend a value to an existing value (only on strings)     |
-- |  132	| AS_MSG_OP_MC_TOUCH   | Memcache-compatible touch (does not change generation)     |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/proto.h

local TYPES_OPS = {
     [1] = "AS_MSG_OP_READ",
     [2] = "AS_MSG_OP_WRITE",
     [3] = "AS_MSG_OP_CDT_READ",
     [4] = "AS_MSG_OP_CDT_MODIFY",
     [5] = "AS_MSG_OP_INCR",
     [6] = "Unused",
     [7] = "Unused",
     [8] = "Unused",
     [9] = "AS_MSG_OP_APPEND",
    [10] = "AS_MSG_OP_PREPEND",
    [11] = "AS_MSG_OP_TOUCH",
   [129] = "AS_MSG_OP_MC_INCR",
   [130] = "AS_MSG_OP_MC_APPEND",
   [131] = "AS_MSG_OP_MC_PREPEND",
   [132] = "AS_MSG_OP_MC_TOUCH",
}

-- Bin Data Types

-- | Value |             Name             |  Type   |
-- |------:|:-----------------------------|:--------|
-- |   0	| AS_PARTICLE_TYPE_NULL	       | String  |
-- |   1	| AS_PARTICLE_TYPE_INTEGER     | Integer |
-- |   2	| AS_PARTICLE_TYPE_FLOAT       | Double  |
-- |   3	| AS_PARTICLE_TYPE_STRING      | String  |
-- |   4	| AS_PARTICLE_TYPE_BLOB	       | Bytes   |
-- |   5	| AS_PARTICLE_TYPE_TIMESTAMP   | String  |
-- |   6	| AS_PARTICLE_TYPE_UNUSED_6    | String  |
-- |   7	| AS_PARTICLE_TYPE_JAVA_BLOB   | Bytes   |
-- |   8	| AS_PARTICLE_TYPE_CSHARP_BLOB | Bytes   |
-- |   9	| AS_PARTICLE_TYPE_PYTHON_BLOB | Bytes   |
-- |  10	| AS_PARTICLE_TYPE_RUBY_BLOB   | Bytes   |
-- |  11	| AS_PARTICLE_TYPE_PHP_BLOB	   | Bytes   |
-- |  12	| AS_PARTICLE_TYPE_ERLANG_BLOB | Bytes   |
-- |  19	| AS_PARTICLE_TYPE_MAP         | String  |
-- |  20	| AS_PARTICLE_TYPE_LIST        | String  |
-- |  23	| AS_PARTICLE_TYPE_GEOJSON	   | String  |
-- |  24	| AS_PARTICLE_TYPE_MAX         | Bytes   |
-- |  24	| AS_PARTICLE_TYPE_BAD         | Bytes   |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/base/datamodel.h

local TYPES_AS_PARTICLE = {
     [0] = "AS_PARTICLE_TYPE_NULL",
     [1] = "AS_PARTICLE_TYPE_INTEGER",
     [2] = "AS_PARTICLE_TYPE_FLOAT",
     [3] = "AS_PARTICLE_TYPE_STRING",
     [4] = "AS_PARTICLE_TYPE_BLOB",
     [5] = "AS_PARTICLE_TYPE_TIMESTAMP",
     [6] = "AS_PARTICLE_TYPE_UNUSED_6",
     [7] = "AS_PARTICLE_TYPE_JAVA_BLOB",
     [8] = "AS_PARTICLE_TYPE_CSHARP_BLOB",
     [9] = "AS_PARTICLE_TYPE_PYTHON_BLOB",
    [10] = "AS_PARTICLE_TYPE_RUBY_BLOB",
    [11] = "AS_PARTICLE_TYPE_PHP_BLOB",
    [12] = "AS_PARTICLE_TYPE_ERLANG_BLOB",
    [19] = "AS_PARTICLE_TYPE_MAP",
    [20] = "AS_PARTICLE_TYPE_LIST",
    [23] = "AS_PARTICLE_TYPE_GEOJSON",
    [24] = "AS_PARTICLE_TYPE_MAX",
}

local function void() end

local function handler_uint64_to_number(x)
   return x:uint64():tonumber()
end

local function handler_uint(x)
   return x:uint()
end

local message_operation_table = {
   { 0,                                          MSG_OPERATIONS_VALUES_SIZE_LENGTH, handler = handler_uint64_to_number, "size"            },
   { MSG_OPERATIONS_VALUES_SIZE_LENGTH,          1,                                 handler = void,                     "op"              },
   { MSG_OPERATIONS_VALUES_OP_LENGTH,            1,                                 handler = handler_uint,             "bin_data_type"   },
   { MSG_OPERATIONS_VALUES_BIN_DATA_TYPE_LENGTH, 1,                                 handler = void,                     "bin_version"     },
   { MSG_OPERATIONS_VALUES_BIN_VERSION_LENGTH,   1,                                 handler = handler_uint,             "bin_name_length" },
   { MSG_OPERATIONS_VALUES_BIN_NAME_LENGTH,      0,                                 handler = void,                     "bin_name"        },
}

-- Create a Proto Object

local aerospike_msg_operations  = Proto("AerospikeOperations",     "Aerospike Operations")

-- Proto header fields

local message_operations = {
   size             = ProtoField.uint32 ("operations.size",            "Size",            base.DEC),
   op               = ProtoField.uint8  ("operations.op",              "Op",              base.DEC,  TYPES_OPS),
   bin_data_type    = ProtoField.uint8  ("operations.bin_data_type",   "Bin data type",   base.DEC,  TYPES_AS_PARTICLE),
   bin_version      = ProtoField.uint8  ("operations.bin_version",     "Bin version",     base.DEC),
   bin_name_length  = ProtoField.uint8  ("operations.bin_name_length", "Bin name length", base.DEC),
   bin_name         = ProtoField.string ("operations.bin_name",        "Bin name"),
   data_str         = ProtoField.string ("operations.data_str",        "Data string"),
   data_int         = ProtoField.uint64 ("operations.data_int",        "Data integer",    base.DEC),
   data_double      = ProtoField.double ("operations.data_double",     "Data float",      base.DEC),
   data_bytes       = ProtoField.bytes  ("operations.bytes",           "Data bytes",      base.NONE),
}

local TYPES_AS_PARTICLE_DATA_TYPE = {
     [0] = message_operations.data_str,     -- AS_PARTICLE_TYPE_NULL
     [1] = message_operations.data_int,     -- AS_PARTICLE_TYPE_INTEGER
     [2] = message_operations.data_double,  -- AS_PARTICLE_TYPE_FLOAT
     [3] = message_operations.data_str,     -- AS_PARTICLE_TYPE_STRING
     [4] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_BLOB
     [5] = message_operations.data_str,     -- AS_PARTICLE_TYPE_TIMESTAMP
     [6] = message_operations.data_str,     -- AS_PARTICLE_TYPE_UNUSED_6
     [7] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_JAVA_BLOB
     [8] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_CSHARP_BLOB
     [9] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_PYTHON_BLOB
    [10] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_RUBY_BLOB
    [11] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_PHP_BLOB
    [12] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_ERLANG_BLOB
    [19] = message_operations.data_str,     -- AS_PARTICLE_TYPE_MAP
    [20] = message_operations.data_str,     -- AS_PARTICLE_TYPE_LIST
    [23] = message_operations.data_str,     -- AS_PARTICLE_TYPE_GEOJSON
    [24] = message_operations.data_bytes,   -- AS_PARTICLE_TYPE_MAX
}

-- Register the protocol fields

aerospike_msg_operations.fields  = message_operations

-- ### Functions

local function update_aerospike_msg_operation_data_type (tvbuf, subtree, bin_data_type, offset, data_length)
   local data_tvbr = tvbuf:range(offset, data_length)

   subtree:add(TYPES_AS_PARTICLE_DATA_TYPE[bin_data_type], data_tvbr)
end

local function dissect_aerospike_msg_operation (tvbuf, subtree, operations_start)
   local offset = operations_start
   local size, bin_data_type, bin_name_length, data_length

   for i,j in ipairs(message_operation_table) do
      local value, tvbr
      for p,q in ipairs(j) do
         if p == 1 then
            offset = offset + q
         elseif p == 2 then
            if q == 0 then -- bin_name_length
               bin_name_length = message_operation_table[i-1][4]
               q = bin_name_length
            end
            tvbr = tvbuf:range(offset, q)
            if j.handler then
               value = j.handler(tvbr)
               table.insert(j, 4, value) -- size, bin_data_type, bin_name_length
            end
         end
      end
      subtree:add(message_operations[j[3]], tvbr)
   end

   size          = message_operation_table[1][4]
   bin_data_type = message_operation_table[3][4]
   data_length   = size - (bin_name_length + 4)
   offset        = offset + bin_name_length

   update_aerospike_msg_operation_data_type(tvbuf, subtree, bin_data_type, offset, data_length)
   return (offset + data_length)
end

local function dissect_aerospike_msg_operations (tvbuf, tree, operations_values_start)
   local operations_start = operations_values_start

   local operations_tvbr = tvbuf:range(operations_values_start)
   local subtree = tree:add(aerospike_msg_operations, operations_tvbr)

   local operations_count_tvbr = tvbuf:range(MSG_OPERATIONS_START, MSG_OPERATIONS_LENGTH)
   local operations_count = operations_count_tvbr:uint()

   for i=1,operations_count,1 do
      operations_start = dissect_aerospike_msg_operation(tvbuf, subtree, operations_start)
   end
   return operations_start
end

local function dissect_aerospike_batch (tvbuf, subtree, fields_start, packet_type, visited)
   local batch_start = fields_start + MSG_FIELDS_VALUES_SIZE_LENGTH + 1
   local batch_total_tvbr = tvbuf:range(batch_start)
   local batchtree = subtree:add(aerospike_batch_proto, batch_total_tvbr)

   -- Read size
   local batch_length_tvbr = tvbuf:range(batch_start, BATCH_SIZE)
   local batch_length = batch_length_tvbr:uint()
   batchtree:add(batch_fields.size, batch_length_tvbr)
   batch_start = batch_start + BATCH_SIZE

   -- Allow batch reads to be inline
   local inline_reads_tvbr = tvbuf:range(batch_start, BATCH_ALLOW_INLINE_SIZE)
   batchtree:add(batch_fields.inline, inline_reads_tvbr)
   batch_start = batch_start + BATCH_ALLOW_INLINE_SIZE

   for j=1,batch_length,1 do
      local origin = batch_start
      local field_count, item_tvbr, full_header = 0, 0, 0
      local batchitem_tvbr = tvbuf:range(batch_start)
      local batchitemtree = batchtree:add(aerospike_batch_item_proto, batchitem_tvbr)

      -- Read index
      local index_tvbr = tvbuf:range(batch_start, BATCH_INDEX_SIZE)
      batchitemtree:add(batch_item_fields.index, index_tvbr)
      batch_start = batch_start + BATCH_INDEX_SIZE

      -- Read digest
      local digest_tvbr = tvbuf:range(batch_start, BATCH_DIGEST_SIZE)
      batchitemtree:add(batch_item_fields.digest, digest_tvbr)
      batch_start = batch_start + BATCH_DIGEST_SIZE

      -- Update hotkey statistics
      if (not visited) then
        local digest_value = digest_tvbr:bytes()
        update_hotkeys(tostring(digest_value), packet_type)
      end

      -- Read Full Header
      local full_header_tvbr = tvbuf:range(batch_start, BATCH_USE_FULL_HEADER_SIZE)
      batchitemtree:add(batch_item_fields.full_header, full_header_tvbr)
      batch_start = batch_start + BATCH_USE_FULL_HEADER_SIZE
      full_header = full_header_tvbr:uint()

      if full_header == 0 then
         -- Read ReadAttr
         local read_attr_tvbr = tvbuf:range(batch_start, BATCH_READ_ATTR_SIZE)
         batchitemtree:add(batch_item_fields.read_attr, read_attr_tvbr)
         batch_start = batch_start + BATCH_READ_ATTR_SIZE

         -- Read Field Count
         local field_count_tvbr = tvbuf:range(batch_start, BATCH_FIELD_COUNT)
         batchitemtree:add(batch_item_fields.field_count, field_count_tvbr)
         batch_start = batch_start + BATCH_FIELD_COUNT

         -- Read Number of Bins
         local number_of_bins_tvbr = tvbuf:range(batch_start, BATCH_NUMBER_OF_BINS)
         local number_of_bins = number_of_bins_tvbr:uint64():tonumber()
         batchitemtree:add(batch_item_fields.number_of_bins, number_of_bins_tvbr)
         batch_start = batch_start + BATCH_NUMBER_OF_BINS

         -- Read namespace length and value
         local namespace_tvbr = tvbuf:range(batch_start, BATCH_NAMESPACE_SIZE)
         local namespace_length = namespace_tvbr:uint64():tonumber()
         batchitemtree:add(batch_item_fields.namespace_length, namespace_tvbr)
         batch_start = batch_start + BATCH_NAMESPACE_SIZE

         local namespace_value_tvbr = tvbuf:range(batch_start, namespace_length)
         batchitemtree:add(batch_item_fields.value, namespace_value_tvbr)
         batch_start = batch_start + namespace_length

         if number_of_bins > 0 then
            -- Read Bins length and value
            local bins_length_tvbr = tvbuf:range(batch_start, BATCH_BINS_COUNT_SIZE)
            local bins_length_value = bins_length_tvbr:uint64():tonumber()
            batchitemtree:add(batch_item_fields.bins_count, bins_length_tvbr)
            batch_start = batch_start + BATCH_BINS_COUNT_SIZE

            local bins_value_tvbr = tvbuf:range(batch_start, bins_length_value)
            batchitemtree:add(batch_item_fields.value, bins_value_tvbr)
            batch_start = batch_start + bins_length_value
         end
      end
   end
end

local function dissect_aerospike_msg_fields (tvbuf, tree, data, count, packet_type, visited)
   local fields_start = data
   local field_size = 0

   local fields_tvbr = tvbuf:range(fields_start)
   local subtree = tree:add(aerospike_msg_fields, fields_tvbr)

   for i=1,count,1 do
      local size_tvbr = tvbuf:range(fields_start, MSG_FIELDS_VALUES_SIZE_LENGTH)
      local size = size_tvbr:uint64():tonumber()
      field_size = field_size + size
      subtree:add(message_fields.size, size_tvbr)

      local type_tvbr = tvbuf:range(fields_start + MSG_FIELDS_VALUES_SIZE_LENGTH, 1)
      local type = type_tvbr:uint()
      subtree:add(message_fields.field_type, type_tvbr)

      if TYPES_MSG_FIELDS[type] == "AS_MSG_FIELD_TYPE_BATCH" then
         dissect_aerospike_batch(tvbuf, subtree, fields_start, packet_type, visited)
      else
         local data_tvbr = tvbuf:range(fields_start + MSG_FIELDS_VALUES_SIZE_LENGTH + 1, size - 1)
         local data_value = data_tvbr:bytes()
         subtree:add(TYPES_MSG_FIELDS_DATA_TYPE[type], data_tvbr)

         -- Update hotkey statistics
         if type == 4 and (not visited) then
            update_hotkeys(tostring(data_value), packet_type)
         end
      end

      fields_start = fields_start +
         MSG_FIELDS_VALUES_SIZE_LENGTH +
         1 + size - 1
   end

   local field_length = fields_start - MSG_FIELDS_VALUES_START
   subtree:set_len(field_length)
   return fields_start
end

local function update_info_tree(tvbr, subsubtree, start, value)
   local info = info_selection[start]
   local info_tree = subsubtree:add(info[1], tvbr, nil, ": "..value) -- aerospike_infoX

   for _,y in ipairs(info[3]) do                -- infoX_order
      info_tree:add(info[2][y], tvbr)           -- infoX_fields
   end
end

local function dissect_aerospike_msg (tvbuf, subtree, data, size, packet_type, visited)
   local operations_start, next_header_start = 0, 0
   local fields_count, ops_count = 0, 0

   while (data < size) do
      operations_start, next_header_start = 0, 0
      fields_count, ops_count = 0, 0

      local data_tvbr = tvbuf:range(data, MSG_HEADER_LENGTH)
      local subsubtree = subtree:add(aerospike_msg_header, data_tvbr)

      for _,v in ipairs(message_header_table) do
         local start, length, attribute = 0, 0, ""
         for p,q in ipairs(v) do
            if p == 1 then
               start = q
            elseif p == 2 then
               length = q
            else
               attribute = q
            end
         end
         local tvbr = tvbuf:range(data, length)
         if start == MSG_INFO1_START or start == MSG_INFO2_START or start == MSG_INFO3_START then
            local value = tvbr:uint()
            update_info_tree(tvbr, subsubtree, start, value)
         else
            if start == MSG_NFIELDS_START then
               fields_count = tvbr:uint64():tonumber()
            elseif start == MSG_NOPS_START then
               ops_count = tvbr:uint64():tonumber()
            end
            subsubtree:add(message_header[attribute], tvbr)
         end
         data = data + length
      end

      if fields_count > 0 then
         operations_start = dissect_aerospike_msg_fields(tvbuf, subtree, data, fields_count, packet_type, visited)
         data = operations_start
      end

      if ops_count > 0 then
         next_header_start = dissect_aerospike_msg_operations(tvbuf, subtree, operations_start)
         data = next_header_start
      end
   end
end

-- The following creates the callback function for the dissector.
-- It's the same as doing "fpm_proto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.

function aerospike_proto.dissector(tvbuf, pktinfo, root)
   local pktlen = tvbuf:len()
   local data, cumulative_size = 0, 0
   local packet_type = 0

   pktinfo.cols.protocol:set("Aerospike")

   while (data < pktlen) do
      -- Dissect the version field 
      local header_version_tvbr = tvbuf:range(data + PROTO_VERSION_START, PROTO_VERSION_LENGTH)

      -- Dissect the type field
      local header_type_tvbr = tvbuf:range(data + PROTO_HEADER_START, PROTO_HEADER_LENGTH)
      local header_type_val  = header_type_tvbr:uint()

      -- Dissect the size field
      local size_tvbr = tvbuf:range(data + INFO_SIZE_START, INFO_SIZE_LENGTH)
      local size      = size_tvbr:uint64()

      if header_type_val == PROTO_TYPE_INFO then        -- INFO
      
         local tree = root:add(aerospike_info_proto, tvbuf:range(0, pktlen))
         dissect_aerospike_info(tvbuf, tree, size)
         data = data + size + MSG_HEADER_SZ_START
         
      elseif header_type_val == PROTO_TYPE_MSG then     -- MSG
      
         local subtree = root:add(aerospike_msg_proto, tvbuf:range(data + PROTO_VERSION_START, size:tonumber() + MSG_HEADER_SZ_START))
         
         subtree:add(message_proto_fields.version, header_version_tvbr)
         subtree:add(message_proto_fields.type, header_type_tvbr)
         subtree:add(message_proto_fields.size, size_tvbr)
         
         data = data + MSG_HEADER_SZ_START
         cumulative_size = cumulative_size + size + MSG_HEADER_SZ_START

         if pktinfo.src_port == default_settings.aerospike_port then
            packet_type = PACKET_RESPONSE
         elseif pktinfo.dst_port == default_settings.aerospike_port then
            packet_type = PACKET_REQUEST
         end

         dissect_aerospike_msg(tvbuf, subtree, data, cumulative_size, packet_type, pktinfo.visited)
         data = data + size:tonumber()
      else
         return 0
      end
   end

   return pktlen
end

-- ## Heartbeat

-- Heartbeat protocol

-- >   +---------------------+------------------------+
-- >   |   Message Header    |     Message Fields     |
-- >   +---------------------+------------------------+

-- Message Header

-- >   +-------------+------+
-- >   |    size     | type |
-- >   +-------------+------+
-- >   0             4      6

-- Constants

local HB_HEADER_SZ_START    = 0
local HB_HEADER_SZ_LENGTH   = 4
local HB_HEADER_TYPE_START  = 4
local HB_HEADER_TYPE_LENGTH = 2

-- Header Type

-- | Value |         Name        |
-- |------:|:--------------------|
-- |   0   | M_TYPE_FABRIC       |
-- |   1   | M_TYPE_HEARTBEAT_V2 |
-- |   2   | M_TYPE_PAXOS        |
-- |   3   | M_TYPE_MIGRATE      |
-- |   4   | M_TYPE_PROXY        |
-- |   5   | M_TYPE_HEARTBEAT    |
-- |   6   | M_TYPE_CLUSTERING   |
-- |   7   | M_TYPE_RW           |
-- |   8   | M_TYPE_INFO         |
-- |   9   | M_TYPE_EXCHANGE     |
-- |  10   | M_TYPE_UNUSED_10    |
-- |  11   | M_TYPE_XDR          |
-- |  12   | M_TYPE_UNUSED_12    |
-- |  13   | M_TYPE_UNUSED_13    |
-- |  14   | M_TYPE_UNUSED_14    |
-- |  15   | M_TYPE_SMD          |
-- |  16   | M_TYPE_UNUSED_16    |
-- |  17   | M_TYPE_UNUSED_17    |
-- |  18   | M_TYPE_MAX          |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/cf/include/msg.h

local HEARTBEAT_MSG_HEADER_TYPE = {
    [0] = "M_TYPE_FABRIC",
    [1] = "M_TYPE_HEARTBEAT_V2",
    [2] = "M_TYPE_PAXOS",
    [3] = "M_TYPE_MIGRATE",
    [4] = "M_TYPE_PROXY",
    [5] = "M_TYPE_HEARTBEAT",
    [6] = "M_TYPE_CLUSTERING",
    [7] = "M_TYPE_RW",
    [8] = "M_TYPE_INFO",
    [9] = "M_TYPE_EXCHANGE",
   [10] = "M_TYPE_UNUSED_10",
   [11] = "M_TYPE_XDR",
   [12] = "M_TYPE_UNUSED_12",
   [13] = "M_TYPE_UNUSED_13",
   [14] = "M_TYPE_UNUSED_14",
   [15] = "M_TYPE_SMD",
   [16] = "M_TYPE_UNUSED_16",
   [17] = "M_TYPE_UNUSED_17",
   [18] = "M_TYPE_MAX",
}

-- Message Fields

-- >   +----------------------------+---------------------------+--------+
-- >   |   Message Field Header 1   |  Message Field Header 2   |  ...   |
-- >   +----------------------------+---------------------------+--------+

-- Message Field Header

-- >   +---------+------+-------------------+
-- >   |   ID    | Type |      Content      |
-- >   +---------+------+-------------------+
-- >        2        1         Array

-- Constants

local HB_FIELD_ID_LENGTH   = 2
local HB_FIELD_TYPE_LENGTH = 1

-- Heartbeat Message Header ID Type

-- | Value |             ID               |
-- |------:|:-----------------------------|
-- |   0   | AS_HB_MSG_ID                 |
-- |   1   | AS_HB_MSG_TYPE               |
-- |   2   | AS_HB_MSG_NODE               |
-- |   3   | AS_HB_MSG_CLUSTER_NAME       |
-- |   4   | AS_HB_MSG_HLC_TIMESTAMP      |
-- |   5   | AS_HB_MSG_ENDPOINTS          |
-- |   6   | AS_HB_MSG_COMPRESSED_PAYLOAD |
-- |   7   | AS_HB_MSG_INFO_REQUEST       |
-- |   8   | AS_HB_MSG_INFO_REPLY         |
-- |   9   | AS_HB_MSG_FABRIC_DATA        |
-- |  10   | AS_HB_MSG_HB_DATA            |
-- |  11   | AS_HB_MSG_PAXOS_DATA         |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/include/fabric/hb.h

local HEARTBEAT_MSG_ID = {
   [0] = "AS_HB_MSG_ID",
   [1] = "AS_HB_MSG_TYPE",
   [2] = "AS_HB_MSG_NODE",
   [3] = "AS_HB_MSG_CLUSTER_NAME",
   [4] = "AS_HB_MSG_HLC_TIMESTAMP",
   [5] = "AS_HB_MSG_ENDPOINTS",
   [6] = "AS_HB_MSG_COMPRESSED_PAYLOAD",
   [7] = "AS_HB_MSG_INFO_REQUEST",
   [8] = "AS_HB_MSG_INFO_REPLY",
   [9] = "AS_HB_MSG_FABRIC_DATA",
  [10] = "AS_HB_MSG_HB_DATA",
  [11] = "AS_HB_MSG_PAXOS_DATA",
}

-- Heartbeat message template

-- |        ID                    |     Type    |
-- |:-----------------------------|:------------|
-- | AS_HB_MSG_ID                 | M_FT_UINT32 |
-- | AS_HB_MSG_TYPE               | M_FT_UINT32 |
-- | AS_HB_MSG_NODE               | M_FT_UINT64 |
-- | AS_HB_MSG_CLUSTER_NAME       | M_FT_STR    |
-- | AS_HB_MSG_HLC_TIMESTAMP      | M_FT_UINT64 |
-- | AS_HB_MSG_ENDPOINTS          | M_FT_BUF    |
-- | AS_HB_MSG_COMPRESSED_PAYLOAD | M_FT_BUF    |
-- | AS_HB_MSG_INFO_REQUEST       | M_FT_BUF    |
-- | AS_HB_MSG_INFO_REPLY         | M_FT_BUF    |
-- | AS_HB_MSG_FABRIC_DATA        | M_FT_BUF    |
-- | AS_HB_MSG_HB_DATA            | M_FT_BUF    |
-- | AS_HB_MSG_PAXOS_DATA         | M_FT_BUF    |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/as/src/fabric/hb.c

-- Message Field Type

-- | Value |        Type       |
-- |------:|:------------------|
-- |   1   | M_FT_UINT32       |
-- |   2   | M_FT_UNUSED_2     |
-- |   3   | M_FT_UINT64       |
-- |   4   | M_FT_UNUSED_4     |
-- |   5   | M_FT_STR          |
-- |   6   | M_FT_BUF          |
-- |   7   | M_FT_ARRAY_UINT32 |
-- |   8   | M_FT_ARRAY_UINT64 |
-- |   9   | M_FT_ARRAY_BUF    |
-- |  10   | M_FT_ARRAY_STR    |
-- |  11   | M_FT_MSGPACK      |

-- Source: https://github.com/aerospike/aerospike-server/blob/master/cf/include/msg.h

-- Heartbeat Message Header ID Type mapping with Message Field Type size

local field_header_type_size = {
    [1] =  4,
    [2] = -1,
    [3] =  8,
    [4] = -1,
    [5] =  0,
    [6] =  0,
    [7] =  4,
    [8] =  8,
    [9] =  0,
   [10] =  0,
   [11] =  0,
}

-- Create a Proto objects

local heartbeat_proto           = Proto("AerospikeHeartbeat",        "Aerospike Heartbeat")
local heartbeat_message_proto   = Proto("AerospikeHeartbeatMessage", "Aerospike Heartbeat Message")

-- Proto header fields

local heartbeat_header_fields = {
   size       = ProtoField.uint32 ("heartbeat.size", "Size", base.DEC),
   field_type = ProtoField.uint16 ("heartbeat.type", "Field Type", base.DEC, HEARTBEAT_MSG_HEADER_TYPE),
}

local heartbeat_message_fields = {
   id         = ProtoField.uint16 ("heartbeat_message.id",    "ID",           base.DEC, HEARTBEAT_MSG_ID),
   type       = ProtoField.uint8  ("heartbeat_message.type",  "Message Type", base.DEC),
   size       = ProtoField.uint32 ("heartbeat_message.size",  "Size",         base.DEC),
   data_bytes = ProtoField.bytes  ("heartbeat_message.bytes", "Data bytes",   base.NONE),
}

-- Register the protocol fields

heartbeat_proto.fields           = heartbeat_header_fields
heartbeat_message_proto.fields   = heartbeat_message_fields

-- Functions

function heartbeat_proto.dissector(tvbuf, pktinfo, root)
   local pktlen = tvbuf:len()
   local data   = 0

   pktinfo.cols.protocol:set("Aerospike")

   local tree = root:add(heartbeat_proto, tvbuf:range(0, pktlen))

   -- Dissect the size field
   local size_tvbr = tvbuf:range(HB_HEADER_SZ_START, HB_HEADER_SZ_LENGTH)
   tree:add(heartbeat_header_fields.size, size_tvbr)

   -- Dissect the type field
   local header_type_tvbr = tvbuf:range(HB_HEADER_TYPE_START, HB_HEADER_TYPE_LENGTH)
   tree:add(heartbeat_header_fields.field_type, header_type_tvbr)

   data = HB_HEADER_SZ_LENGTH + HB_HEADER_TYPE_LENGTH

   while (data < pktlen) do
      local field_id_tvbr = tvbuf:range(data, HB_FIELD_ID_LENGTH)
      tree:add(heartbeat_message_fields.id, field_id_tvbr)
      data = data + HB_FIELD_ID_LENGTH

      local field_type_tvbr = tvbuf:range(data, HB_FIELD_TYPE_LENGTH)
      local field_type      = field_type_tvbr:uint()
      tree:add(heartbeat_message_fields.type, field_type_tvbr)
      data = data + HB_FIELD_TYPE_LENGTH

      local size = field_header_type_size[field_type]

      if size > 0 then
          local value_tvbr = tvbuf:range(data, size)
          tree:add(heartbeat_message_fields.data_bytes, value_tvbr)
          data = data + size
      elseif size == 0 then
          local value_tvbr = tvbuf:range(data, 4)
          local new_size = value_tvbr:uint64():tonumber()
          tree:add(heartbeat_message_fields.size, value_tvbr)
          data = data + 4

          if new_size > 0 then
             local new_value_tvbr = tvbuf:range(data, new_size)
             tree:add(heartbeat_message_fields.data_bytes, new_value_tvbr)
             data = data + new_size
          end
      else
      end
   end

   return pktlen
end

-- # The Main

local function enable_dissector()
   DissectorTable.get("tcp.port"):add(default_settings.aerospike_port,           aerospike_proto)
   DissectorTable.get("tcp.port"):add(default_settings.heartbeat_mesh_port,      heartbeat_proto)
   DissectorTable.get("udp.port"):add(default_settings.heartbeat_multicast_port, heartbeat_proto)
end

enable_dissector()
