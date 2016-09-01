# Copyright 2014,2015 USTC INFINITE Laboratory
# Copyright 2011,2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
used in
openflow.pof_01
openflow.bypassmanager
openflow.__init__
openflow.util
openflow.pmdatabase
openflow.pofmanager
"""

import struct
import sys
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.util import initHelper
from pox.lib.util import hexdump
from pox.lib.util import assert_type
from pox.lib.packet import packet_base


EMPTY_ETH = EthAddr(None)

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

# _logger = None
_logger = core.getLogger()
def _log (debug=None, info=None, warn=None, error=None):
    if not _logger: return
    if debug: _logger.debug(debug)
    if info: _logger.info(info)
    if warn: _logger.warn(warn)
    if error: _logger.error(error)

# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# XID Management
# ----------------------------------------------------------------------

MAX_XID = 0x7fFFffFF

def XIDGenerator (start=1, stop=MAX_XID):
    i = start
    while True:
        yield i
        i += 1
        if i > stop:
            i = start

def xid_generator (start=1, stop=MAX_XID):
    return XIDGenerator(start, stop).next

def user_xid_generator ():
    return xid_generator(0x80000000, 0xffFFffFF)

generate_xid = xid_generator()

# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# Packing / Unpacking
# ----------------------------------------------------------------------

_PAD = b'\x00'
_PAD2 = _PAD * 2
_PAD3 = _PAD * 3
_PAD4 = _PAD * 4
_PAD5 = _PAD * 5
_PAD6 = _PAD * 6
_PAD7 = _PAD * 7
_PAD8 = _PAD * 8

class Hex2Raw():
    def __init__(self, data, length):
        if isinstance(data, basestring):
            if (len(data) % 2):
                data += '0'
            if len(data) / 2 > length:
                raise RuntimeError("Out of length")
            else:
                self.value = b''.join((chr(int(data[x*2:x*2+2], 16)) for x in range(len(data)/2)))
                self.value += _PAD * (length - len(self.value)) 
        else:
            raise RuntimeError("Expected an instance of string")

    def toRaw(self):
        return self.value

class UnderrunError (RuntimeError):
    """
    Raised when one tries to unpack more data than is available
    """
    pass

def _read (data, offset, length):
    if (len(data) - offset) < length:
        raise UnderrunError("wanted %s bytes but only have %s"
                        % (length, len(data) - offset))
    return (offset + length, data[offset:offset + length])

def _unpack (fmt, data, offset):
    size = struct.calcsize(fmt)
    if (len(data) - offset) < size:
        raise UnderrunError()
    return (offset + size, struct.unpack_from(fmt, data, offset))

def _skip (data, offset, num):
    offset += num
    if offset > len(data):
        raise UnderrunError()
    return offset

def _unpad (data, offset, num):
    (offset, o) = _read(data, offset, num)
    assert len(o.replace("\x00", "")) == 0
    return offset

def _readzs (data, offset, length):
    (offset, d) = _read(data, offset, length)
    d = d.split("\x00", 1)
    assert True if (len(d) == 1) else (len(d[1].replace("\x00", "")) == 0)
    return (offset, d[0])

def _readether (data, offset):
    (offset, d) = _read(data, offset, 6)
    return (offset, EthAddr(d))

def _readip (data, offset, networkOrder=True):
    (offset, d) = _read(data, offset, 4)
    return (offset, IPAddr(d, networkOrder=networkOrder))

def _format_body (body, prefix):
    if hasattr(body, 'show'):
        # TODO: Check this (spacing may well be wrong)
        return body.show(prefix + '  ')
    else:
        return prefix + hexdump(body).replace("\n", "\n" + prefix)

# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# Class decorators
# ----------------------------------------------------------------------
    
_message_type_to_class = {}
_message_class_to_types = {}  # Do we need this?
ofp_type_rev_map = {}
ofp_type_map = {}

def openflow_message (ofp_type, type_val, reply_to=None,
                      request_for=None, switch=False, controller=False):
    ofp_type_rev_map[ofp_type] = type_val  # cc: ofp_type is a string(name) 
    ofp_type_map[type_val] = ofp_type
    def f (c):  # cc: c means class
        c.header_type = type_val
        c._from_switch = switch
        c._from_controller = controller
        _message_type_to_class[type_val] = c
        _message_class_to_types.setdefault(c, set()).add(type_val)
        return c
    return f

def openflow_sc_message (*args, **kw):
    return openflow_message(switch=True, controller=True, *args, **kw)

def openflow_c_message (*args, **kw):
    return openflow_message(controller=True, *args, **kw)

def openflow_s_message (*args, **kw):
    return openflow_message(switch=True, *args, **kw)


_action_type_to_class = {}
_action_class_to_types = {}  # Do we need this?
ofp_action_type_rev_map = {}
ofp_action_type_map = {}

def openflow_action (action_type, type_val):
    ofp_action_type_rev_map[action_type] = type_val
    ofp_action_type_map[type_val] = action_type
    def f (c):
        c.type = type_val  # cc: class variable of ofp_action_base
        _action_type_to_class[type_val] = c
        _action_class_to_types.setdefault(c, set()).add(type_val)
        return c
    return f


_instruction_type_to_class = {}
_instruction_class_to_types = {}
ofp_instruction_type_rev_map = {}
ofp_instruction_type_map = {}

def openflow_instruction (instruction_type, type_val):
    ofp_instruction_type_rev_map[instruction_type] = type_val
    ofp_instruction_type_map[type_val] = instruction_type
    def f (c):
        c.type = type_val  # cc: class variable of ofp_action_base
        _instruction_type_to_class[type_val] = c
        _instruction_class_to_types.setdefault(c, set()).add(type_val)
        return c
    return f

# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# Constants, etc.
# ----------------------------------------------------------------------

# --------------- org.openflow.protocol.OFError ---------------- #
ofp_error_type_rev_map = {  # modified by CC
  'OFPET_HELLO_FAILED'         : 0,
  'OFPET_BAD_REQUEST'          : 1,
  'OFPET_BAD_ACTION'           : 2,
  'OFPET_BAD_INSTRUCTION'      : 3,
  'OFPET_BAD_MATCH'            : 4,
  'OFPET_FLOW_MOD_FAILED'      : 5,
  'OFPET_GROUP_MOD_FAILED'     : 6,
  'OFPET_PORT_MOD_FAILED'      : 7,
  'OFPET_TABLE_MOD_FAILED'     : 8,
  'OFPET_QUEUE_OP_FAILED'      : 9,
  'OFPET_SWITCH_CONFIG_FAILED' : 10,
  'OFPET_ROLE_REQUEST_FAILED'  : 11,
  'OFPET_METER_MOD_FAILED'     : 12,
  'OFPET_TABLE_FEATURES_FAILED': 13,
  'OFPET_SOFTWARE_FAILED'      : 14,
  #'OFPET_COUNTER_MOD_FAILED'   : 15,
  #'OFPET_INSBLOCK_MOD_FAILED'  : 16,
  'OFPET_EXPERIMENTER_ERROR'   : 0xFFFF,
}

ofp_hello_failed_code_rev_map = {
  'OFPHFC_INCOMPATIBLE' : 0,
  'OFPHFC_EPERM'        : 1,
}

ofp_bad_request_code_rev_map = {  # modified by cc
  'OFPBRC_BAD_VERSION'            : 0,
  'OFPBRC_BAD_TYPE'               : 1,
  'OFPBRC_BAD_MULTIPART'          : 2,
  'OFPBRC_BAD_EXPERIMENTER'       : 3,
  'OFPBRC_BAD_EXPERIMENTER_TYPE'  : 4,
  'OFPBRC_EPERM'                  : 5,
  'OFPBRC_BAD_LEN'                : 6,
  'OFPBRC_BUFFER_EMPTY'           : 7,
  'OFPBRC_BUFFER_UNKNOWN'         : 8,
  'OFPBRC_BAD_TABLE_ID'           : 9,
  'OFPBRC_IS_SLAVE'               : 10,
  'OFPBRC_BAD_PORT'               : 11,
  'OFPBRC_BAD_PACKET'             : 12,
  'OFPBRC_MULTIPART_BUFFER_BUFFER_OVERFLOW' : 13,
}

ofp_bad_action_code_rev_map = {  # changed by cc
  'OFPBAC_BAD_TYPE'              : 0,
  'OFPBAC_BAD_LEN'               : 1,
  'OFPBAC_BAD_EXPERIMENTER'      : 2,
  'OFPBAC_BAD_EXPERIMENTER_TYPE' : 3,
  'OFPBAC_BAD_OUT_PORT'          : 4,
  'OFPBAC_BAD_ARGUMENT'          : 5,
  'OFPBAC_EPERM'                 : 6,
  'OFPBAC_TOO_MANY'              : 7,
  'OFPBAC_BAD_QUEUE'             : 8,
  'OFPBAC_BAD_OUT_GROUP'         : 9,
  'OFPBAC_MATCH_INCONSISTENT'    : 10,
  'OFPBAC_UNSUPPORTED_ORDER'     : 11,
  'OFPBAC_BAD_TAG'               : 12,
  'OFPBAC_BAD_SET_TYPE'          : 13,
  'OFPBAC_BAD_SET_LEN'           : 14,
  'OFPBAC_BAD_SET_ARGUMENT'      : 15,
}

ofp_bad_instruction_code_rev_map = {  # added by cc
  'OFPBIC_UNKNOW_INST'                : 0,
  'OFPBIC_UNSUP_INST'                 : 1,
  'OFPBIC_BAD_TABLE_ID'               : 2,
  'OFPBIC_UNSUP_METADATA'             : 3,
  'OFPBIC_UNSUP_METADATA_MASK'        : 4,
  'OFPBIC_BAD_EXPERIMENTER'           : 5,
  'OFPBIC_BAD_EXPERIMENTER_TYPE'      : 6,
  'OFPBIC_BAD_LEN'                    : 7,
  'OFPBIC_EPERM'                      : 8,
  'OFPBIC_TOO_MANY_ACTIONS'           : 9,
  'OFPBIC_TABLE_UNEXIST'              : 17,
  'OFPBIC_ENTRY_UNEXIST'              : 18,
  'OFPBIC_BAD_OFFSET'                 : 19,
  'OFPBIC_JUM_TO_INVALID_INST'        : 20,
}

ofp_bad_match_code_rev_map = {  # added by cc
  'OFPBMC_BAD_TYPE'             : 0,
  'OFPBMC_BAD_LEN'              : 1,
  'OFPBMC_BAD_TAG'              : 2,
  'OFPBMC_BAD_DL_ADDR_MASK'     : 3,
  'OFPBMC_BAD_NW_ADDR_MASK'     : 4,
  'OFPBMC_BAD_WILDCARD'         : 5,
  'OFPBMC_BAD_FIELD'            : 6,
  'OFPBMC_BAD_VALUE'            : 7,
  'OFPBMC_BAD_MASK'             : 8,
  'OFPBMC_BAD_PREERQ'           : 9,
  'OFPBMC_DUP_FIELD'            : 10,
  'OFPBMC_RPERM'                : 11,
}

ofp_flow_mod_failed_code_rev_map = {  # modified by cc
  'OFPFMFC_UNKNOWN'       : 0,
  'OFPFMFC_TABLE_FULL'    : 1,
  'OFPFMFC_BAD_TABLE_ID'  : 2,
  'OFPFMFC_OVERLAP'       : 3,
  'OFPFMFC_EPERM'         : 4,
  'OFPFMFC_BAD_TIMEOUT'   : 5,
  'OFPFMFC_BAD_COMMAND'   : 6,
  'OFPFMFC_BAD_FLAGS'     : 7,
  'OFPFMFC_ENTRY_EXIST'   : 8,
  'OFPFMFC_ENTRY_UNEXIST' : 9,
}

ofp_table_mod_failed_code_rev_map = {  # added by cc according to pofswitch
  'OFPTMFC_UNKNOWN'         : 0,
  'OFPTMFC_BAD_COMMAND'     : 1,
  'OFPTMFC_BAD_TABLE_TYPE'  : 2,
  'OFPTMFC_BAD_TABLE_ID'    : 3,
}

ofp_group_mod_failed_code_rev_map = {  # added by cc
  'OFPGMFC_GROUP_EXISTS'         : 0,
  'OFPGMFC_INVALID_GROUP'        : 1,
  'OFPGMFC_WEIGHT_UNSUPPORTED'   : 2,
  'OFPGMFC_OUT_OF_GROUPS'        : 3,
  'OFPGMFC_OUT_OF_BUCKETS'       : 4,
  'OFPGMFC_CHAINING_UNSUPPORTED' : 5,
  'OFPGMFC_WATCH_UNSUPPORTED'    : 6,
  'OFPGMFC_LOOP'                 : 7,
  'OFPGMFC_UNKNOWN_GROUP'        : 8,
  'OFPGMFC_CHAINED_GROUP'        : 9,
  'OFPGMFC_BAD_TYPE'             : 10,
  'OFPGMFC_BAD_COMMAND'          : 11,
  'OFPGMFC_BAD_BUCKET'           : 12,
  'OFPGMFC_BAD_WATCH'            : 13,
  'OFPGMFC_EPERM'                : 14,
}

ofp_meter_mod_failed_code_rev_map = {  # added by cc
  'OFPMMFC_UNKNOWN'         : 0,
  'OFPMMFC__METER_EXISTS'   : 1,
  'OFPMMFC_INVALID_METER'   : 2,
  'OFPMMFC_UNKNOWN_METER'   : 3,
  'OFPMMFC_BAD_COMMAND'     : 4,
  'OFPMMFC_BAD_FLAGS'       : 5,
  'OFPMMFC_BAD_RATE'        : 6,
  'OFPMMFC_BAD_BURST'       : 7,
  'OFPMMFC_BAD_BAND'        : 8,
  'OFPMMFC_BAD_BAND_VALUE'  : 9,
  'OFPMMFC_OUT_OF_METERS'   : 10,
  'OFPMMFC_OUT_OF_BANDS'    : 11,
}

ofp_counter_mod_failed_code_rev_map = {  # added by cc
    'OFPCMFC_UNKNOWN'           : 0,
    'OFPCMFC_BAD_COUNTER_ID'    : 1,
    'OFPCMFC_BAD_COMMAND'       : 2,
    'OFPCMFC_COUNTER_UNEXIST'   : 3,
    'OFPCMFC_COUNTER_EXIST'     : 4,
}

ofp_port_mod_failed_code_rev_map = {
    'OFPPMFC_BAD_PORT'    : 0,
    'OFPPMFC_BAD_HW_ADDR' : 1,
}

ofp_queue_op_failed_code_rev_map = {
    'OFPQOFC_BAD_PORT'  : 0,
    'OFPQOFC_BAD_QUEUE' : 1,
    'OFPQOFC_EPERM'     : 2,
}

ofp_software_failed_code_rev_map = {  # added by cc
    'OFPSEC_OK'                              : 0,
    'OFPSEC_ALLOCATE_RESOURCE_FAILURE'       : 0x5001,
    'OFPSEC_ADD_EXIST_FLOW'                  : 0x5002,
    'OFPSEC_DELETE_UNEXIST_FLOW'             : 0x5003,
    'OFPSEC_COUNTER_REQUEST_FAILURE'         : 0x5004,
    'OFPSEC_DELETE_NOT_EMPTY_TABLE'          : 0x5005,
    'OFPSEC_INVALID_TABLE_TYPE'              : 0x6000,
    'OFPSEC_INVALID_KEY_LENGTH'              : 0x6001,
    'OFPSEC_INVALID_TABLE_SIZE'              : 0x6002,
    'OFPSEC_INVALID_MATCH_KEY'               : 0x6003,
    'OFPSEC_UNSUPPORT_INSTRUTION_LENGTH'     : 0x6004,
    'OFPSEC_UNSUPPORT_INSTRUTION_TYPE'       : 0x6005,
    'OFPSEC_UNSUPPORT_ACTION_LENGTH'         : 0x6006,
    'OFPSEC_UNSUPPORT_ACTION_TYPE'           : 0x6007,
    'OFPSEC_TABLE_NOT_CREATED'               : 0x6008,
    'OFPSEC_UNSUPPORT_COMMAND'               : 0x6009,
    'OFPSEC_UNSUPPORT_FLOW_TABLE_COMMAND'    : 0x600A,
    'OFPSEC_UPFORWARD_TOO_LARGE_PACKET'      : 0x600B,
    'OFPSEC_CREATE_SOCKET_FAILURE'           : 0x7001,
    'OFPSEC_CONNECT_SERVER_FAILURE'          : 0x7002,
    'OFPSEC_SEND_MSG_FAILURE'                : 0x7003,
    'OFPSEC_RECEIVE_MSG_FAILURE'             : 0x7004,
    'OFPSEC_WRONG_CHANNEL_STATE'             : 0x7005,
    'OFPSEC_WRITE_MSG_QUEUE_FAILURE'         : 0x7006,
    'OFPSEC_READ_MSG_QUEUE_FAILURE'          : 0x7007,
    'OFPSEC_MESSAGE_SIZE_TOO_BIG'            : 0x7008,
    'OFPSEC_IPC_SEND_FAILURE'                : 0x8001,
    'OFPSEC_CREATE_TASK_FAILURE'             : 0x8002,
    'OFPSEC_CREATE_MSGQUEUE_FAILURE'         : 0x8003,
    'OFPSEC_CREATE_TIMER_FAILURE'            : 0x8004,
    'OFPSEC_ERROR'                           : 0xffff,
}

# ------------ org.openflow.protocol.OFPhysicalPort -----------#
ofp_port_config_rev_map = {  # modified by cc
  'OFPPC_PORT_DOWN'    : 1,
  'OFPPC_NO_RECV'      : 4,
  'OFPPC_NO_FWD'       : 32,
  'OFPPC_NO_PACKET_IN' : 64,
}

ofp_port_state_rev_map = {  # modified by cc
  'OFPPS_LINK_DOWN'   : 1,
  'OFPPS_BLOCKED'     : 2,
  'OFPPS_LIVE'        : 4,
}

ofp_port_features_rev_map = {  # modified by cc
  'OFPPF_10MB_HD'    : 1,
  'OFPPF_10MB_FD'    : 2,
  'OFPPF_100MB_HD'   : 4,
  'OFPPF_100MB_FD'   : 8,
  'OFPPF_1GB_HD'     : 16,
  'OFPPF_1GB_FD'     : 32,
  'OFPPF_10GB_FD'    : 64,
  'OFPPF_40GB_FD'    : 128,  # add
  'OFPPF_100GB_FD'   : 256,  # add
  'OFPPF_1TB_FD'     : 512,  # add
  'OFPPF_OTHER'      : 1024,  # add
  'OFPPF_COPPER'     : 2048,
  'OFPPF_FIBER'      : 4096,
  'OFPPF_AUTONEG'    : 8192,
  'OFPPF_PAUSE'      : 16384,
  'OFPPF_PAUSE_ASYM' : 32768,
}

# ------------ org.openflow.protocol.OFFeaturesReply ---------- #
ofp_capabilities_rev_map = {  # modified by cc
  'OFPC_FLOW_STATS'   : 1,
  'OFPC_TABLE_STATS'  : 2,
  'OFPC_PORT_STATS'   : 4,
  'OFPC_GROUP_STATS'  : 8,
  #'OFPC_RESERVED'     : 16,
  'OFPC_IP_REASM'     : 32,
  'OFPC_QUEUE_STATS'  : 64,
  #'OFPC_ARP_MATCH_IP' : 128,
  'OFPC_PORT_BLOCKED' : 256,
}

# ----------- org.openflow.protocol.OFSwitchConfig ----------- #
ofp_config_flags_rev_map = {
  'OFPC_FRAG_NORMAL' : 0,
  'OFPC_FRAG_DROP'   : 1,
  'OFPC_FRAG_REASM'  : 2,
  'OFPC_FRAG_MASK'   : 3,
}

# ---------------- org.openflow.protocol.OFFlowMod ---------------- #
ofp_flow_mod_command_rev_map = {
  'OFPFC_ADD'           : 0,
  'OFPFC_MODIFY'        : 1,
  'OFPFC_MODIFY_STRICT' : 2,
  'OFPFC_DELETE'        : 3,
  'OFPFC_DELETE_STRICT' : 4,
}

ofp_flow_mod_flags_rev_map = {
  'OFPFF_SEND_FLOW_REM' : 1,
  'OFPFF_CHECK_OVERLAP' : 2,
  'OFPFF_EMERG'         : 4,
}

# ---------- org.openflow.protocol.OFMultipartReply -------------- #
ofp_stats_reply_flags_rev_map = {  # edit by CC
  'OFPSF_REPLY_MORE' : 1,  # or 'REPLY_MORE'?
}

# -------------- org.openflow.protocol.OFPacketIn ---------------- #
ofp_packet_in_reason_rev_map = {  # modified by CC
  'OFPR_NO_MATCH'    : 0,
  'OFPR_ACTION'      : 1,
  'OFPR_INVALID_TTL' : 2,
}

# -------------- org.openflow.protocol.OFFlowRemoved ------------- #
ofp_flow_removed_reason_rev_map = {
  'OFPRR_IDLE_TIMEOUT' : 0,
  'OFPRR_HARD_TIMEOUT' : 1,
  'OFPRR_DELETE'       : 2,
}

# -------------- org.openflow.protocol.OFPortStatus -------------- #
ofp_port_reason_rev_map = {
  'OFPPR_ADD'    : 0,
  'OFPPR_DELETE' : 1,
  'OFPPR_MODIFY' : 2,
}

# ---------------- org.openflow.protocol.OFPort ---------------- #
# modified by     CC
ofp_port_rev_map = {
  'OFPP_MAX'        : 65280,
  'OFPP_IN_PORT'    : 65528,
  'OFPP_TABLE'      : 65529,
  'OFPP_NORMAL'     : 65530,
  'OFPP_FLOOD'      : 65531,
  'OFPP_ALL'        : 65532,
  'OFPP_CONTROLLER' : 65533,
  'OFPP_LOCAL'      : 65534,
  'OFPP_ANY'        : 65535,  # changed from 'OFPP_NONE'
}

# -------------- org.openflow.protocol.OFMatch ------------- #
# modified by cc
ofp_flow_wildcards_rev_map = {
  'OFPFW_IN_PORT'      : 1,  # Switch input port
  'OFPFW_DL_VLAN'      : 2,  # VLAN id
  'OFPFW_DL_SRC'       : 4,  # Ethernet source address
  'OFPFW_DL_DST'       : 8,  # Ethernet destination address
  'OFPFW_DL_TYPE'      : 16,  # Ethernet frame type
  'OFPFW_NW_PROTO'     : 32,  # IP protocol
  'OFPFW_TP_SRC'       : 64,  # TCP/UDP source port
  'OFPFW_TP_DST'       : 128,  # TCP/UDP destination port
  'OFPFW_DL_VLAN_PCP'  : 1048576,  # VLAN priority, 1<<20
  'OFPFW_NW_TOS'       : 1 << 21,
}
OFPFW_NW_DST_BITS = 6
OFPFW_NW_SRC_BITS = 6
OFPFW_NW_SRC_SHIFT = 8
OFPFW_NW_DST_SHIFT = 14
OFPFW_NW_SRC_ALL = 8192  # 32 << OFPFW_NW_SRC_SHIFT
OFPFW_NW_SRC_MASK = 16128  # ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT
OFPFW_NW_DST_ALL = 524288  # 32 << OFPFW_NW_DST_SHIFT
OFPFW_NW_DST_MASK = 1032192  # ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT
# Note: Need to handle all flags that are set in this.
# glob-all masks in the packet handling methods.
# (Esp. ofp_match.from_packet)
# Otherwise, packets are not being matched as they should
OFPFW_ALL = ((1 << 22) - 1)

# -------------- org.openflow.protocol.OFGroupMod ------------- #
ofp_group_type_rev_map = {  # add by cc
    'OFPGT_ALL'       : 0,
    'OFPGT_SELECT'    : 1,
    'OFPGT_INDIRECT'  : 2,
    'OFPGT_FF'        : 3,
}
                            
ofp_group_mod_cmd_rev_map = {  # add by cc
    'OFPGC_ADD'      : 0,
    'OFPGC_MODIFY'   : 1,
    'OFPGC_DELETE'   : 2,
}

# -------------- org.openflow.protocol.OFMeterMod ------------- #
ofp_meter_mod_com_rev_map = {  # add by cc
    'OFPMC_ADD'     : 0,
    'OFPMC_MODIFY'  : 1,
    'OFPMC_DELETE'  : 2,
}

# -------------- org.openflow.protocol.OFCounter ------------- #
ofp_counter_mod_com_rev_map = {  # add by cc
    'OFPCC_ADD'        : 0,
    'OFPCC_DELETE'     : 1,
    'OFPCC_CLEAR'      : 2,
    'OFPCC_QUERY'      : 3,
    'OFPCC_QUERYREPLY' : 4,
}

# ---------- org.openflow.protocol.table.OFTableType ---------- #
ofp_table_type_rev_map = {  # add by cc
    'OF_MM_TABLE'        : 0,  # MaskedMatch Table
    'OF_LPM_TABLE'       : 1,  # LongestPrefixMatch Table
    'OF_EM_TABLE'        : 2,  # ExactMatch Table
    'OF_LINEAR_TABLE'    : 3,  # Linear Table
    'OF_MAX_TABLE_TYPE'  : 4,
}

# ---------- org.openflow.protocol.table.OFTableMod ---------- #
ofp_table_mod_cmd_rev_map = {  # add by cc
    'OFPTC_ADD'          : 0,
    'OFPTC_MODIFY'       : 1,
    'OFPTC_DELETE'       : 2,
}

# ------- org.openflow.protocol.table.OFFlowTableResource ------ #
ofp_resource_report_type_rev_map = {
    'OFRRT_FLOW_TABLE'   : 0,
}

# ------ org.openflow.protocol.instruction.OFInstructionCalculateField ------ #
ofp_calc_type_rev_map = {  # add by cc 
    'OFPCT_ADD'         : 0,  # +
    'OFPCT_SUBTRACT'    : 1,  # -
    'OFPCT_LEFT_SHIFT'  : 2,  # <<
    'OFPCT_RIGHT_SHIFT' : 3,  # >>
    'OFPCT_BITWISE_ADD' : 4,  # &
    'OFPCT_BITWISE_OR'  : 5,  # |
    'OFPCT_BITWISE_XOR' : 6,  # ^
    'OFPCT_BITWISE_NOR' : 7,
}

# -------------- org.openflow.protocol.action.OFActionDrop ------------- #
ofp_drop_reason_rev_map = {  # add by cc
    'OFPDT_TIMEOUT'  : 0,
    'OFPDT_HIT_MISS' : 1,
    'OFPDT_UNKNOW'   : 2
}

NO_BUFFER = 4294967295

# -------------- org.openflow.protocol.OFGlobal -------------- #
OFP_INVALID_VALUE = 0xFFFFFFFF  # Define invalid value. {@value}.
OFP_NAME_MAX_LENGTH = 64  # Define the length of device name.
OFP_ERROR_STRING_MAX_LENGTH = 256  # Define the max length of error string.
OFP_PACKET_IN_MAX_LENGTH = 2048  # Define the max length of packetin. {@value}.
OFP_MAX_FIELD_LENGTH_IN_BYTE = 16  # Define the max length in byte unit of match field. {@value}.
OFP_MAX_MATCH_FIELD_NUM = 8  # Define the max number of match field in one flow entry. {@value}.
OFP_MAX_INSTRUCTION_NUM = 6  # Define the max instruction number of one flow entry. {@value}.
OFP_MAX_PROTOCOL_FIELD_NUM = 8  # Define the max field number of one protocol. {@value}.
OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION = 6  # Define the max action number in one instruction. {@value}.
OFP_MAX_ACTION_NUMBER_PER_GROUP = 6  # Define the max action number in one group. {@value}.
OFP_MAX_ACTION_LENGTH = 44  # Define the max action length in unit of byte. {@value}.
OFP_MAX_INSTRUCTION_LENGTH = (8 + 8 + OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION * (OFP_MAX_ACTION_LENGTH + 4))  # Define the max instruction length in unit of byte. {@value}.



# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# Structure definitions
# ----------------------------------------------------------------------

class _ofp_meta (type):
    """
    Metaclass for ofp messages/structures
    This takes care of making len() work as desired.
    modified by cc
    """
    @classmethod
    def __len__ (cls):
        try:
            return cls.__len__()
        except:
            return cls._MIN_LENGTH


class ofp_base (object):
    """
    Base class for OpenFlow messages/structures

    You should implement a __len__ method.  If your length is fixed, it
    should be a static method.  If your length is not fixed, you should
    implement a __len__ instance method and set a class level _MIN_LENGTH
    attribute to your minimum length.
    """
    __metaclass__ = _ofp_meta

    def _assert (self):
        r = self._validate()
        if r is not None:
            raise RuntimeError(r)
            return False  # Never reached
        return True

    def _validate (self):
        return None

    def __ne__ (self, other):
        return not self.__eq__(other)

    @classmethod
    def unpack_new (cls, raw, offset=0):
        """
        Unpacks wire format into the appropriate message object.
    
        Returns newoffset,object
        """
        o = cls()
        r, length = o.unpack(raw, offset)  # cc: r -> new offset
        assert (r - offset) == length, o
        return (r, o)
    

# 1. Openflow Header
class ofp_header (ofp_base):
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        self.version = OFP_VERSION
        # self.header_type = None # Set via class decorator
        self._xid = None
        if 'header_type' in kw: 
            self.header_type = kw.pop('header_type')
        initHelper(self, kw)

    @property
    def xid (self):
        if self._xid is None:
            self._xid = generate_xid()
        return self._xid

    @xid.setter
    def xid (self, val):
        self._xid = val

    def _validate (self):
        if self.header_type not in ofp_type_map:
            return "type is not a known message type"
        return None

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += struct.pack("!BBHL", self.version, self.header_type,
            len(self), self.xid)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        return offset, length

    def _unpack_header (self, raw, offset):
        offset, (self.version, self.header_type, length, self.xid) = \
            _unpack("!BBHL", raw, offset)
        return offset, length

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if self.version != other.version: return False
        if self.header_type != other.header_type: return False
        if len(self) != len(other): return False
        if self.xid != other.xid: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'version: ' + str(self.version) + '\n'
        outstr += prefix + 'type:    ' + str(self.header_type)  # + '\n'
        outstr += " (" + ofp_type_map.get(self.header_type, "Unknown") + ")\n"
        try:
            outstr += prefix + 'length:  ' + str(len(self)) + '\n'
        except:
            pass
        outstr += prefix + 'xid:     ' + str(self.xid) + '\n'
        return outstr

    def __str__ (self):
        return self.__class__.__name__ + "\n  " + self.show('  ').strip()


class ofp_action_base (ofp_base):
    """
    edit by CC
    Base class for actions
    """
    _MIN_LENGTH = 4
    _MAX_LENGTH = 4 + OFP_MAX_ACTION_LENGTH  # 48
    type = None
    
    def __init__(self, **kw):
        initHelper(self, kw)

    def _validate(self):
        if self.type not in ofp_action_type_map:
            return "type is not a known action type"
        return

    def pack(self):
        assert self._assert()

        packed = b""
        packed += struct.pack("!HH", self.type, len(self))
        return packed
    
    def unpack(self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        return offset, length
    
    def _unpack_header(self, raw, offset):
        offset, (self.type, length) = _unpack("!HH", raw, offset)
        return offset, length
        
    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.type != other.type: return False
        if len(self) != len(other): return False
        return True
    
    def __str__(self):
        return self.__class__.__name__ + "\n  " + self.show('  ').strip()
    
    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'type:   ' + str(self.type)
        outstr += " (" + ofp_action_type_map.get(self.type, "Unknown") + ")\n"
        outstr += prefix + 'length: ' + str(len(self)) + '\n'
        return outstr

    @classmethod
    def unpack_new (cls, raw, offset=0):
        """
        Unpacks wire format into the appropriate action object.
        Returns newoffset,object
        """
        o = cls()
        r = o.unpack(raw, offset)
        assert (r - offset) == len(o), o
        return (r, o)


class ofp_instruction_base (ofp_base):
    """
    edit by cc
    Base class for instruction
    """
    _MIN_LENGTH = 8
    _MAX_LENGTH = OFP_MAX_INSTRUCTION_LENGTH  # 304
    type = None
    
    def __init__(self, **kw):
        initHelper(self, kw)

    def _validate(self):
        if self.type not in ofp_instruction_type_map:
            return "type is not a known instruction type"
        return

    def pack(self):
        assert self._assert()

        packed = b""
        packed += struct.pack("!HH", self.type, len(self))
        packed += _PAD4
        return packed
    
    def unpack(self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        return offset, length
    
    def _unpack_header(self, raw, offset):
        offset, (self.type, length) = _unpack("!HH", raw, offset)
        offset = _skip(raw, offset, 4)
        return offset, length
        
    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.type != other.type: return False
        if len(self) != len(other): return False
        return True
    
    def __str__(self):
        return self.__class__.__name__ + "\n  " + self.show('  ').strip()
    
    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'type:   ' + str(self.type)
        outstr += " (" + ofp_instruction_type_map.get(self.type, "Unknown") + ")\n"
        outstr += prefix + 'length: ' + str(len(self)) + '\n'
        return outstr

    @classmethod
    def unpack_new (cls, raw, offset=0):
        """
        Unpacks wire format into the appropriate action object.
    
        Returns newoffset,object
        """
        o = cls()
        r = o.unpack(raw, offset)
        assert (r - offset) == len(o), o
        return (r, o)
    
    
# 2. Common Structures
# #2.1 Port Structures
class ofp_phy_port (ofp_base):
    """
    modified by cc
    """
    _MIN_LENGTH = 120
    
    def __init__ (self, **kw):
        self.port_id = 0  # 4 bytes
        self.device_id = 0  # 4 bytes
        self.hw_addr = EMPTY_ETH  # 6 bytes
        self.name = b""  # 64 bytes
        self.config = 0  # 4 bytes
        self.state = 0  # 4 bytes
        self.curr = 0  # 4 bytes
        self.advertised = 0  # 4 bytes
        self.supported = 0  # 4 bytes
        self.peer = 0  # 4 bytes
        self.curr_speed = 0  # 4 bytes
        self.max_speed = 0  # 4 bytes
        self.of_enable = 0  # 1 bytes
        
        initHelper(self, kw)

    def enable_config (self, mask):
        """
        Turn on selected config bits
        """
        return self.set_config(0xffFFffFF, mask)

    def disable_config (self, mask):
        """
        Turn off selected config bits
        """
        return self.set_config(0, mask)

    def set_config (self, config, mask):
        """
        Updates the specified config bits
    
        Returns which bits were changed
        """
        old = self.config
        self.config &= ~mask
        self.config |= config
        return old ^ self.config
    
    def __str__ (self):
        return "%s:%i" % (self.name, self.port_id)

    def _validate (self):
        if isinstance(self.hw_addr, bytes) and len(self.hw_addr) == 6:
            pass
        elif not isinstance(self.hw_addr, EthAddr):
            return "hw_addr is not a valid format"
        if len(self.name) > OFP_MAX_PORT_NAME_LEN:
            return "name is too long"
        return None

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += struct.pack("!LL", self.port_id, self.device_id)
        packed += (self.hw_addr if isinstance(self.hw_addr, bytes) else
                   self.hw_addr.toRaw())
        packed += _PAD2
        packed += self.name.ljust(OFP_MAX_PORT_NAME_LEN, '\0')
        packed += struct.pack("!LLLLLLLLB", self.config, self.state, self.curr, self.advertised,
            self.supported, self.peer, self.curr_speed, self.max_speed, self.of_enable)
        packed += _PAD * 7
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, (self.port_id, self.device_id) = _unpack("!LL", raw, offset)
        offset, self.hw_addr = _readether(raw, offset)
        offset = _skip(raw, offset, 2)
        offset, self.name = _readzs(raw, offset, OFP_MAX_PORT_NAME_LEN)
        offset, (self.config, self.state, self.curr, self.advertised, self.supported, self.peer,
            self.curr_speed, self.max_speed, self.of_enable) = _unpack("!LLLLLLLLB", raw, offset)
        offset = _skip(raw, offset, 7)
        assert offset - _offset == len(self)
        return offset
  
    @staticmethod
    def __len__ ():
        return 120  # changed from 48 to 120

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if self.port_id != other.port_id: return False
        if self.device_id != other.device_id: return False
        if self.hw_addr != other.hw_addr: return False
        if self.name != other.name: return False
        if self.config != other.config: return False
        if self.state != other.state: return False
        if self.curr != other.curr: return False
        if self.advertised != other.advertised: return False
        if self.supported != other.supported: return False
        if self.peer != other.peer: return False
        if self.curr_speed != other.curr_speed: return False
        if self.max_speed != other.max_speed: return False
        if self.of_enable != other.of_enable: return False 
        return True

    def __cmp__ (self, other):
        if type(other) != type(self): return id(self) - id(other)
        if self.port_id < other.port_id: return -1
        if self.port_id > other.port_id: return 1
        if self == other: return 0
        return id(self) - id(other)

    def __hash__(self, *args, **kwargs):
        return hash(self.port_id) ^ hash(self.hw_addr) ^ \
               hash(self.name) ^ hash(self.config) ^ \
               hash(self.state) ^ hash(self.curr) ^ \
               hash(self.advertised) ^ hash(self.supported) + \
               hash(self.peer)

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'port_id:    ' + str(self.port_id) + '\n'
        outstr += prefix + 'device_id:  ' + str(self.device_id) + '\n'
        outstr += prefix + 'hw_addr:    ' + str(EthAddr(self.hw_addr)) + '\n'
        outstr += prefix + 'name:       ' + str(self.name) + '\n'
        outstr += prefix + 'config:     ' + str(self.config) + '\n'
        outstr += prefix + 'state:      ' + str(self.state) + '\n'
        outstr += prefix + 'curr:       ' + str(self.curr) + '\n'
        outstr += prefix + 'advertised: ' + str(self.advertised) + '\n'
        outstr += prefix + 'supported:  ' + str(self.supported) + '\n'
        outstr += prefix + 'peer:       ' + str(self.peer) + '\n'
        outstr += prefix + 'curr_speed: ' + str(self.curr_speed) + '\n'
        outstr += prefix + 'max_speed:  ' + str(self.max_speed) + '\n'
        outstr += prefix + 'of_enable:  ' + str(self.of_enable) + '\n'
        return outstr

    def __repr__(self):
        return self.show()
    
# #2.3 Flow Match Structures
class ofp_match(ofp_base):
    """
    edit by cc
    according to org.openflow.protocol.OFMatch
    """
    _MIN_LENGTH = 40

    def __init__(self, **kw):
        self.wildcards = OFPFW_ALL  # 4 bytes
        self.data_layer_dst = _PAD6  # 6 bytes
        self.data_layer_src = _PAD6  # 6 bytes
        self.data_layer_virtual_lan = -1  # 2 bytes
        self.data_layer_virtual_lan_priority_code_point = 0  # 1 bytes
        self.data_layer_type = 0  # 2 bytes
        self.input_port = 0  # 2 bytes
        self.network_protocol = 0  # 1 bytes
        self.network_type_of_service = 0  # 1 byte
        self.network_src = 0  # 4 bytes
        self.network_dst = 0  # 4 bytes
        self.transport_dst = 0  # 2 bytes
        self.transport_src = 0  # 2 bytes

        initHelper(self, kw)

    def pack(self):
        assert self._assert()
        
        packed = b""
        packed += struct.pack("!LH", self.wildcards, self.input_port)
        packed += self.data_layer_src
        packed += self.data_layer_dst
        packed += struct.pack("!HB", self.data_layer_virtual_lan,
            self.data_layer_virtual_lan_priority_code_point)
        packed += _PAD
        packed += struct.pack("!HBB", self.data_layer_type,
            self.network_type_of_service, self.network_protocol)
        packed += _PAD2
        packed += struct.pack("!LLHH", self.network_src, self.network_dst,
            self.transport_src, self.transport_dst)
        return packed

    def unpack(self, raw, offset=0):
        offset, (self.wildcards, self.input_port) = _unpack("!LH", raw, offset)
        offset, self.data_layer_src = _read(raw, offset, 6)
        offset, self.data_layer_dst = _read(raw, offset, 6)
        offset, (self.data_layer_virtual_lan, self.data_layer_virtual_lan_priority_code_point) = \
            _unpack("HB", raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.data_layer_type, self.network_type_of_service, self.network_protocol) = \
            _unpack("!HBB", raw, offset)
        offset = _skip(raw, offset, 2)
        offset, (self.network_src, self.network_dst, self.transport_src,
            self.transport_dst) = _unpack("!LLHH", raw, offset)
        return offset

    @staticmethod
    def __len__():
        return ofp_match._MAX_LENGTH  # 40

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.wildcards != other.wildcards: return False
        if self.input_port != other.input_port: return False
        if self.data_layer_src != other.data_layer_src: return False
        if self.data_layer_dst != other.data_layer_dst: return False
        if self.data_layer_virtual_lan != other.data_layer_virtual_lan: return False
        if self.data_layer_virtual_lan_priority_code_point != other.data_layer_virtual_lan_priority_code_point: return False
        if self.data_layer_type != other.data_layer_type: return False
        if self.network_type_of_service != other.network_type_of_service: return False
        if self.network_protocol != other.network_protocol: return False
        if self.network_src != other.network_src: return False
        if self.network_dst != other.network_dst: return False
        if self.transport_src != other.transport_src: return False
        if self.transport_dst != other.transport_dst: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'wildcards:        ' + str(self.wildcards) + '\n'
        outstr += prefix + 'input_port:       ' + str(self.input_port) + '\n'
        outstr += prefix + 'data_layer_src:   ' + str(self.data_layer_src) + '\n'
        outstr += prefix + 'data_layer_dst:   ' + str(self.data_layer_dst) + '\n'
        outstr += prefix + 'data_layer_virtual_lan:  ' + str(self.data_layer_virtual_lan) + '\n'
        outstr += prefix + 'data_layer_virtual_lan_priority_code_point: ' + str(self.data_layer_virtual_lan_priority_code_point) + '\n'
        outstr += prefix + 'data_layer_type:  ' + str(self.data_layer_type) + '\n'
        outstr += prefix + 'network_type_of_service: ' + str(self.network_type_of_service) + '\n'
        outstr += prefix + 'network_protocol: ' + str(self.network_protocol) + '\n'
        outstr += prefix + 'network_src:      ' + str(self.network_src) + '\n'
        outstr += prefix + 'network_dst:      ' + str(self.network_dst) + '\n'
        outstr += prefix + 'transport_src:    ' + str(self.transport_src) + '\n'
        outstr += prefix + 'transport_dst:    ' + str(self.transport_dst) + '\n'
        return outstr
    
class ofp_match20 (ofp_base):  # add by cc
    _MIN_LENGTH = 8
    _METADATA_FIELD_ID = 0xffff
    
    def __init__(self, **kw):
        self.field_name = ""
        self.field_id = 0  # 2 bytes
        self.offset = 0    # 2 bytes
        self.length = 0    # 2 bytes
        
        initHelper(self, kw)
    
    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.field_id != other.field_id: return False
        if self.offset != other.offset: return False
        if self.length != other.length: return False
        return True
  
    def __len__(self):
        return 8
    
    def pack(self):
        assert self._assert()
        
        packed = b""
        packed += struct.pack("!h" , self.field_id)
        packed += struct.pack("!H" , self.offset)
        packed += struct.pack("!H" , self.length)
        packed += _PAD2
        return packed

    def unpack(self, raw, offset=0):
        _offset = offset
        offset, (self.field_id, self.offset, self.length) = _unpack('!HHH', raw, offset)
        offset = _skip(raw, offset, 2)
        assert offset - _offset == len(self)
        return offset

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'field_name: ' + self.field_name + '\n' 
        outstr += prefix + 'field_id:   ' + str(self.field_id) + '\n' 
        outstr += prefix + 'offset:     ' + str(self.offset) + '\n' 
        outstr += prefix + 'length:     ' + str(self.length) + '\n' 
        return outstr
    
    def __str__ (self):
        return self.__class__.__name__ + "\n  " + self.show('  ').strip()
    

class ofp_matchx(ofp_base):  # add by cc
    _MIN_LENGTH = 40
    
    def __init__(self, **kw):
        for k,v in kw.iteritems():
            if not hasattr(self, k):
                setattr(self, k, v)
        
        if 'match20' in kw:
            match = kw['match20']
            self.field_name = match.field_name
            self.field_id = match.field_id  # 2 bytes
            self.offset = match.offset  # 2 bytes
            self.length = match.length  # 2 bytes
        else:
            self.field_name = ""
            self.field_id = 0
            self.offset = 0
            self.length = 0
            
        if 'value' in kw:
            self.value = kw['value']  # 16 bytes
        else:
            self.value = []
            
        if 'mask' in kw:
            self.mask = kw['mask']  # 16 bytes
        else:
            self.mask = []
        
        initHelper(self, kw)
    
    def set_value(self, hexstring):
        if(len(hexstring) % 2):
            hexstring += '0'
        if(len(hexstring) > OFP_MAX_FIELD_LENGTH_IN_BYTE * 2):
            #hexstring = hexstring[:OFP_MAX_FIELD_LENGTH_IN_BYTE * 2]
            _log(error = "out of length in ofp_matchx.value")
        self.value = []
        for i in xrange(0, len(hexstring) / 2):
            int_c = int(hexstring[i*2:i*2+2],16)
            #print (hexstring[i*2:i*2+2]),int_c
            self.value.append(int_c)
    
    def set_mask(self,hexstring):
        if (len(hexstring) % 2):
            hexstring +='0'
        if (len(hexstring) > OFP_MAX_FIELD_LENGTH_IN_BYTE * 2):
            #hexstring=hexstring[:OFP_MAX_FIELD_LENGTH_IN_BYTE * 2]
            _log(error = "out of length in ofp_matchx.mask")
        self.mask=[]
        for i in xrange(0,len(hexstring)/2):
            int_c=int(hexstring[i*2:i*2+2], 16)    
            #print (hexstring[i*2:i*2+2]),int_c
            self.mask.append(int_c)

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.field_id != other.field_id: return False
        if self.offset != other.offset: return False
        if self.length != other.length: return False       
        if self.value != other.value: return False
        if self.mask != other.mask: return False
        return True
  
    def __len__(self):
        return 40
    
    def pack(self):
        assert self._assert()

        packed = b""
        packed += struct.pack("!h" , self.field_id)
        packed += struct.pack("!H" , self.offset)
        packed += struct.pack("!H" , self.length)
        packed += _PAD2
        """
        for i in self.value:
            packed += struct.pack("!B", int(i))
        packed += _PAD * (OFP_MAX_FIELD_LENGTH_IN_BYTE - len(self.value))
        """
        #packed += b''.join((chr(int(self.value[x*2:x*2+2], 16)) for x in range(len(self.value)/2)))
        """
        for i in self.value:
            packed += chr(i)
        packed += _PAD * (OFP_MAX_FIELD_LENGTH_IN_BYTE - len(self.value)/2)
        """
        """
        for i in self.mask:
            packed += struct.pack("!B", int(i))
        packed += _PAD * (OFP_MAX_FIELD_LENGTH_IN_BYTE - len(self.mask))
        """
        #packed += '\xff'*OFP_MAX_FIELD_LENGTH_IN_BYTE
        packed += Hex2Raw(self.value, OFP_MAX_FIELD_LENGTH_IN_BYTE).toRaw()
        packed += Hex2Raw(self.mask, OFP_MAX_FIELD_LENGTH_IN_BYTE).toRaw()
        return packed

    def unpack(self, raw, offset=0):
        _offset = offset
        offset, (self.field_id, self.offset, self.length) = _unpack('!HHH', raw, offset)
        offset = _skip(raw, offset, 2)
        
        for _ in xrange(0, OFP_MAX_FIELD_LENGTH_IN_BYTE):
            offset, temp_value = _unpack('!B', raw, offset)
            self.value.append(temp_value)
            
        for _ in xrange(0, OFP_MAX_FIELD_LENGTH_IN_BYTE):
            offset, temp_mask = _unpack('!B', raw, offset)
            self.mask.append(temp_mask)
            
        assert offset - _offset == len(self)
        return offset

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'field_id: ' + str(self.field_id) + '\n' 
        outstr += prefix + 'offset:   ' + str(self.offset) + '\n' 
        outstr += prefix + 'length:   ' + str(self.length) + '\n' 
        outstr += prefix + 'value:    ' + str(self.value) + '\n' 
        outstr += prefix + 'mask:     ' + str(self.mask) + '\n'
        return outstr

# #2.4 Table Resource Structures
class ofp_table_resource(ofp_base):  # used in ofp_resource_report
    _MIN_LENGTH = 16

    def __init__(self, **kw):
        self.device_id = 0  # 4 bytes
        self.table_type = 0  # 1 byte, ofp_table_type
        self.table_num = 0   # 1 byte
        self.key_length = 0  # 2 bytes
        self.total_size = 0  # 4 bytes
        
        initHelper(self, kw)
    
    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.device_id != other.device_id: return False
        if self.table_type != other.table_type: return False
        if self.table_num != other.table_num: return False
        if self.key_length != other.key_length: return False
        if self.total_size != other.total_size: return False
        return True
  
    def __len__(self):
        return 16
    
    def pack(self):
        assert self._assert()
        
        packed = b""
        packed += struct.pack("!LBBHL", self.device_id, self.table_type,
            self.table_num, self.key_length, self.total_size)
        packed += _PAD4
        return packed

    def unpack(self, raw, offset=0):
        _offset = offset
        offset, (self.device_id, self.table_type, self.table_num,
            self.key_length, self.total_size) = _unpack('!LBBHL', raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'device_id:  ' + str(self.device_id) + '\n' 
        outstr += prefix + 'table_type: ' + str(self.table_type)
        # outstr += " (" + ofp_table_type_map[self.table_type] + ")\n"
        outstr += " (" + ofp_table_type_map.get(self.table_type, "Unknown") + ")\n"
        outstr += prefix + 'table_num:  ' + str(self.table_num) + '\n' 
        outstr += prefix + 'key_length: ' + str(self.key_length) + '\n' 
        outstr += prefix + 'total_size: ' + str(self.total_size) + '\n' 
        return outstr

# #2.5 Flow Table Structures   
class ofp_flow_table(ofp_base):  # used in ofp_table_mod
    _MIN_LENGTH = OFP_NAME_MAX_LENGTH + 16  # 80
    _MAX_LENGTH = OFP_NAME_MAX_LENGTH + 16 + OFP_MAX_MATCH_FIELD_NUM * ofp_match20._MIN_LENGTH  # 144
    
    def __init__ (self, **kw):
        self.command = 0  # 1 bytes, ofp_table_mod_command
        self.table_id = 0  # 1 bytes
        self.table_type = 0  # 1 bytes, ofp_table_type
        self.match_field_num = 0  # 1 bytes
        self.table_size = 0  # 4 bytes
        self.key_length = 0  # 2 bytes
        self.table_name = None  # 64 bytes, String
        self.match_field_list = []  # ofp_match20, 8 * 8 = 64 bytes
        
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += struct.pack("!BBBBLH" , self.command, self.table_id, self.table_type,
                              self.match_field_num, self.table_size, self.key_length)
        packed += _PAD6
        packed += self.table_name.ljust(OFP_NAME_MAX_LENGTH, '\0')
        for m in self.match_field_list:  # match20
            packed += m.pack()
        if len(self.match_field_list) < OFP_MAX_MATCH_FIELD_NUM:
            packed += _PAD * (OFP_MAX_MATCH_FIELD_NUM - len(self.match_field_list)) * ofp_match20._MIN_LENGTH
        return packed
    
    def unpack (self, raw, offset=0):
        _offset = offset
        offset, (self.command, self.table_id, self.table_type, self.match_field_num,
                 self.table_size, self.key_length) = _unpack('!BBBBLH', raw, offset)        
        offset = _skip(raw, offset, 6)
        offset, self.name = _readzs(raw, offset, OFP_NAME_MAX_LENGTH)
        for _ in xrange(0, OFP_MAX_MATCH_FIELD_NUM):
            m = ofp_match20()
            offset = m.unpack(raw, offset)
            self.match_field_list.append(m)
            
        assert offset - _offset == len(self)
        return offset
    
    @staticmethod
    def __len__ ():
        return ofp_flow_table._MAX_LENGTH
    
    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.command != other.command: return False
        if self.table_id != other.table_id: return False
        if self.table_type != other.table_type: return False
        if self.match_field_num != other.match_field_num: return False
        if self.table_size != other.table_size: return False
        if self.key_length != other.key_length: return False
        if self.table_name != other.table_name: return False
        if self.match_field_list != other.match_field_num: return False
        return True
    
    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'command:          ' + str(self.command)
        # outstr += ' (' + ofp_table_mod_cmd_map[self.command] + ')\n' 
        outstr += ' (' + ofp_table_mod_cmd_map.get(self.command, "Unknown") + ')\n' 
        outstr += prefix + 'table_id:         ' + str(self.table_id) + '\n' 
        outstr += prefix + 'table_type:       ' + str(self.table_type)
        # outstr += ' (' + ofp_table_type_map[self.table_type] + ')\n'
        outstr += ' (' + ofp_table_type_map.get(self.table_type, "Unknown") + ')\n'
        outstr += prefix + 'match_field_num:  ' + str(self.match_field_num) + '\n' 
        outstr += prefix + 'table_size:       ' + str(self.table_size) + '\n' 
        outstr += prefix + 'key_length:       ' + str(self.key_length) + '\n' 
        outstr += prefix + 'table_name:       ' + str(self.table_name) + '\n' 
        outstr += prefix + 'match_field_list: \n'
        for match in self.match_field_list:
            outstr += match.show(prefix + '  ')
        return outstr
    
# #2.6 Counter Structures    
class ofp_counter(ofp_base):
    _MIN_LENGTH = 24
    
    def __init__(self, **kw):
        self.command = 0         # 1 bytes, ofp_counter_mod_com, 0:OFPCC_ADD, 1:OFPCC_DELETE, 2:OFPCC_CLEAR, 3:OFPCC_QUERY
        self.counter_id = 0      # 4 bytes
        self.counter_value = 0   # 8 bytes
        self.byte_value = 0      # 8 bytes
        
        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += struct.pack("!B", self.command)
        packed += _PAD3
        packed += struct.pack("!LQQ", self.counter_id, self.counter_value,
                              self.byte_value)
        return packed
    
    def unpack (self, raw, offset=0):
        offset, (self.command,) = _unpack("!B", raw, offset)
        offset = _skip(raw, offset, 3)
        offset, (self.counter_id, self.counter_value, self.byte_value) = \
            _unpack("!LQQ", raw, offset)
        return offset

    @staticmethod
    def __len__ ():
        return 24

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'command:       ' + str(self.command)
        outstr += ' (' + ofp_counter_mod_com_map.get(self.command, "Unknown") + ')\n'
        outstr += prefix + 'counter_id:    ' + str(self.counter_id) + '\n'
        outstr += prefix + 'counter_value: ' + str(self.counter_value) + '\n'
        outstr += prefix + 'byte_value:    ' + str(self.byte_value) + '\n'
        return outstr 
    
# ---------------------------------------------------------------------
# OFAction
# ---------------------------------------------------------------------
    
@openflow_action('OFPAT_OUTPUT', 0)
class ofp_action_output (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionSetField
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8 + ofp_match20._MIN_LENGTH
    _MIN_LENGTH = 20

    def __init__(self, **kw):
        self.port_id_value_type = 0  # 1 bytes
        self.metadata_offset = 0  # 2 bytes
        self.metadata_length = 0  # 2 bytes
        self.packet_offset = 0  # 2 bytes
        self.port_id = 0  # 4 bytes
        self.port_id_field = None  # ofp_match20

        initHelper(self, kw)

    def pack(self):
        assert self._assert()

        packed = b""
        packed += ofp_action_base.pack(self)

        packed += struct.pack("!B", self.port_id_value_type)
        packed += _PAD
        packed += struct.pack("!HHH", self.metadata_offset,
            self.metadata_length, self.packet_offset)
        if self.port_id_value_type == 0:
            packed += struct.pack("!L", self.port_id)
            packed += _PAD4
        elif self.port_id_value_type == 1 and self.port_id_field != None:
            packed += self.port_id_field.pack()  # ofp_match20.pack
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
        return packed

    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)

        offset, self.port_id_value_type = _unpack('!B', raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.metadata_offset, self.metadata_length,
            self.packet_offset) = _unpack("!HHH", raw, offset)
        if self.port_id_value_type == 0:
            offset, self.port_id = _unpack('!L', raw, offset)
            offset = _skip(raw, offset , 4)
            self.port_id_field = None
        elif self.port_id_value_type == 1:
            self.port_id = 0
            self.port_id_field = ofp_match20()
            offset = self.port_id_field.unpack(raw, offset)
        else:
            self.port_id = 0
            self.port_id_field = None
            offset = _skip(raw, offset , ofp_match20._MIN_LENGTH)
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_action_output._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.port_id_value_type != other.port_id_value_type: return False
        if self.metadata_offset != other.metadata_offset: return False
        if self.metadata_length != other.metadata_length: return False
        if self.packet_offset != other.packet_offset: return False
        if self.port_id != other.port_id: return False
        if self.port_id_field != other.port_id_field: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'port_id_value_type: ' + str(self.port_id_value_type) + '\n'
        outstr += prefix + 'metadata_offset:    ' + str(self.metadata_offset) + '\n'
        outstr += prefix + 'metadata_length:    ' + str(self.metadata_length) + '\n'
        outstr += prefix + 'packet_offset:      ' + str(self.packet_offset) + '\n'
        if self.port_id_value_type == 0:
            outstr += prefix + 'port_id:            ' + str(self.port_id) + '\n'
        if self.port_id_value_type == 1:
            outstr += prefix + 'port_id_field: \n'
            outstr += self.port_id_field.show(prefix + '  ')
        return outstr

@openflow_action('OFPAT_SET_FIELD', 1)
class ofp_action_set_field (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionSetField
    """
    _MIN_LENGTH = ofp_action_base._MIN_LENGTH + ofp_matchx._MIN_LENGTH
    #_MIN_LENGTH = 44

    def __init__ (self, **kw):
        self.field_setting = None  # ofp_matchx
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)

        packed += self.field_setting.pack()
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        self.field_setting = ofp_matchx()
        offset = self.field_setting.unpack(raw, offset)  # ofp_matchx.upack
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return ofp_action_set_field._MIN_LENGTH  # 44

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.field_setting != other.field_setting: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'field_setting: \n'
        outstr += self.field_setting.show(prefix + '  ')
        return outstr
    
@openflow_action('OFPAT_SET_FIELD_FROM_METADATA', 2)
class ofp_action_set_field_from_metadata (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionSetFieldFromMetadata
    """
    _MIN_LENGTH = ofp_action_base._MIN_LENGTH + ofp_match20._MIN_LENGTH + 8
    #_MIN_LENGTH = 20
    
    def __init__ (self, **kw):
        self.field_setting = None   # ofp_match20
        self.metadata_offset = 0    # 2 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += self.field_setting.pack()
        packed += struct.pack("!H", self.metadata_offset)
        packed += _PAD6
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        self.field_setting = ofp_match20()
        offset = self.field_setting.unpack(raw, offset)  # ofp_matchx.upack
        offset, self.metadata_offset = _unpack("!H", raw, offset)
        offset = _skip(raw, offset, 6)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_set_field_from_metadata._MIN_LENGTH  # 20

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.field_setting != other.field_setting: return False
        if self.metadata_offset != other.metadata_offset: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'field_setting: \n'
        outstr += self.field_setting.show(prefix + '  ')
        outstr += prefix + 'metadata_offset: ' + str(self.metadata_offset) + '\n'
        return outstr
    
@openflow_action('OFPAT_MODIFY_FIELD', 3)
class ofp_action_modify_field (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionModifyField
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + ofp_match20._MIN_LENGTH + 8
    _MIN_LENGTH = 20
    
    def __init__ (self, **kw):
        self.match_field = ofp_match20()  # ofp_match20
        self.increment = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += self.match_field.pack()
        packed += struct.pack("!L", self.increment)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        self.match_field = ofp_match20()
        offset = self.match_field.unpack(raw, offset)  # ofp_matchx.upack
        offset, self.increment = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_modify_field._MIN_LENGTH  # 20

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.match_field != other.match_field: return False
        if self.increment != other.increment: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'match_field: \n'
        outstr += self.match_field.show(prefix + '  ')
        outstr += prefix + 'increment: ' + str(self.increment) + '\n'
        return outstr
    
@openflow_action('OFPAT_ADD_FIELD', 4)
class ofp_action_add_field (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionAddField
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8 + OFP_MAX_FIELD_LENGTH_IN_BYTE
    _MIN_LENGTH = 28
    
    def __init__ (self, **kw):
        self.field_id = 0  # 2 bytes
        self.field_position = 0  # 2 bytes
        self.field_length = 0  # 4 bytes
        self.field_value = b''  # 16 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!HHL", self.field_id, self.field_position, self.field_length)
        # packed += self.field_value   # 16 bytes
        if len(self.field_value) == 0:
            packed += _PAD * OFP_MAX_FIELD_LENGTH_IN_BYTE
        else:
            if len(self.field_value) > OFP_MAX_FIELD_LENGTH_IN_BYTE:
                _log(error="out of range in field_value")
                return
            else:
                #packed += self.field_value    #FIXME:TORAW
                #packed += _PAD * (OFP_MAX_FIELD_LENGTH_IN_BYTE - len(self.field_value))
                packed += Hex2Raw(self.field_value, OFP_MAX_FIELD_LENGTH_IN_BYTE).toRaw()
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, (self.field_id, self.field_position, self.field_length) = \
            _unpack("!HHL", raw, offset)
        offset, self.field_value = _read(raw, offset, OFP_MAX_FIELD_LENGTH_IN_BYTE)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_add_field._MIN_LENGTH  # 28

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.field_id != other.field_id: return False
        if self.field_position != other.field_position: return False
        if self.field_length != other.field_length: return False
        if self.field_value != other.field_value: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'field_id:       ' + str(self.field_id) + '\n'
        outstr += prefix + 'field_position: ' + str(self.field_position) + '\n'
        outstr += prefix + 'field_length:   ' + str(self.field_length) + '\n'
        outstr += prefix + 'field_value:    ' + str(self.field_value) + '\n'  # FIXME:
        return outstr
    
@openflow_action('OFPAT_DELETE_FIELD', 5)
class ofp_action_delete_field (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionDeleteField
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + ofp_match20._MIN_LENGTH + 8
    _MIN_LENGTH = 20
    
    def __init__ (self, **kw):
        self.tag_position = 0  # 2 bytes
        self.tag_length_value_type = 0  # 1 bytes
        self.tag_length_value = 0  # 4 bytes
        self.tag_length_field = ofp_match20()  # 8 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!HB", self.tag_position, self.tag_length_value_type)
        packed += _PAD5
        if self.tag_length_value_type == 0:
            packed += struct.pack("!L", self.tag_length_value)
            packed += _PAD4
        elif self.tag_length_value_type == 1 and self.tag_length_field is not None:
            packed += self.tag_length_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, (self.tag_position, self.tag_length_value_type) = _unpack("!HB", raw, offset)
        offset = _skip(raw, offset, 5)
        if self.tag_length_value_type == 0:
            offset, self.tag_length_value = _unpack("!L", raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.tag_length_value_type == 1:
            self.tag_length_value = 0
            offset = self.tag_length_field.unpack(raw, offset)
        else:
            self.tag_length_value = 0
            offset = _skip(raw, offset, ofp_match20._MIN_LENGTH)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_delete_field._MIN_LENGTH  # 20

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.tag_position != other.tag_position: return False
        if self.tag_length_value_type != other.tag_length_value_type: return False
        if self.tag_length_value != other.tag_length_value: return False
        if self.tag_length_field != other.tag_length_field: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'match_field: \n'
        outstr += self.match_field.show(prefix + '  ')
        outstr += prefix + 'tag_position: ' + str(self.tag_position) + '\n'
        outstr += prefix + 'tag_length_value_type: ' + str(self.tag_length_value_type) + '\n'
        outstr += prefix + 'tag_length_value: ' + str(self.tag_length_value) + '\n'
        outstr += prefix + 'tag_length_field: ' + str(self.tag_length_field) + '\n'  # FIXME:
        return outstr

@openflow_action('OFPAT_CALCULATE_CHECKSUM', 6)
class ofp_action_calculate_checksum (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionCalculateCheckSum
    """
    #_MIN_LENGTH = ofp_action_base._MIN_LENGTH + 16
    _MIN_LENGTH = 20
    
    def __init__ (self, **kw):
        self.checksum_pos_type = 0   #1 byte, 0: packet; 1: metadata
        self.calc_pos_type = 0       #1 byte, 0: packet; 1: metadata
        self.checksum_position = 0   # 2 bytes
        self.checksum_length = 0   # 2 bytes
        self.calc_start_position = 0  #2 bytes
        self.calc_length = 0   #2 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!BBHHHH", self.checksum_pos_type, self.calc_pos_type, self.checksum_position,
                              self.checksum_length, self.calc_start_position, self.calc_length)
        packed += _PAD6
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, (self.checksum_pos_type, self.calc_pos_type, self.checksum_position, self.checksum_length,
                 self.calc_start_position, self.calc_length) = _unpack("!BBHHHH", raw, offset)
        offset = _skip(raw, offset, 6)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_calculate_checksum._MIN_LENGTH  # 20

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.checksum_pos_type != other.checksum_pos_type: return False
        if self.calc_pos_type != other.calc_pos_type: return False
        if self.checksum_position != other.checksum_position: return False
        if self.checksum_length != other.checksum_length: return False
        if self.calc_start_position != other.calc_start_position: return False
        if self.calc_length != other.calc_length: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'checksum_pos_type:   ' + str(self.checksum_pos_type) + '\n'
        outstr += prefix + 'calc_pos_type:       ' + str(self.calc_pos_type) + '\n'
        outstr += prefix + 'checksum_position:   ' + str(self.checksum_position) + '\n'
        outstr += prefix + 'checksum_length:     ' + str(self.checksum_length) + '\n'
        outstr += prefix + 'calc_start_position: ' + str(self.calc_start_position) + '\n'
        outstr += prefix + 'calc_length:         ' + str(self.calc_length) + '\n'
        return outstr
    
@openflow_action('OFPAT_GROUP', 7)
class ofp_action_group (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionCalculateCheckSum
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        self.group_id = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!L", self.group_id)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.group_id = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_group._MIN_LENGTH  # 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.group_id != other.group_id: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'group_id: ' + str(self.group_id) + '\n'  # FIXME:
        return outstr
    
@openflow_action('OFPAT_DROP', 8)
class ofp_action_drop (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionDROP
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        self.reason = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!L", self.reason)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.reason = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_drop._MIN_LENGTH  # 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.reason != other.reason: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'reason: ' + str(self.reason)
        outstr += '(' + ofp_drop_reason_map[self.reason] + ')\n'
        return outstr
    
@openflow_action('OFPAT_PACKETIN', 9)
class ofp_action_packetin (ofp_action_base):
    """
    modified by cc
    according to org.openflow.protocol.action.OFActionPacketIn
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        self.reason = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!L", self.reason)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.reason = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_drop._MIN_LENGTH  # 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.reason != other.reason: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'reason: ' + str(self.reason) + '\n'
        return outstr
    
@openflow_action('OFPAT_COUNTER', 10)
class ofp_action_counter (ofp_action_base):
    """
    modified by CC
    according to org.openflow.protocol.action.OFActionCounter
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        self.counter_id = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!L", self.counter_id)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.counter_id = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_counter._MIN_LENGTH  # 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.counter_id != other.counter_id: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'counter_id: ' + str(self.counter_id) + '\n'
        return outstr

@openflow_action('OFPAT_EXPERIMENTER', 11)
class ofp_action_experimenter (ofp_action_base):
    """
    modified by CC
    according to org.openflow.protocol.action.OFActionCounter
    """
    # _MIN_LENGTH = ofp_action_base._MIN_LENGTH + 8
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        self.exterimenter = 0  # 4 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_action_base.pack(self)
        packed += struct.pack("!L", self.exterimenter)
        packed += _PAD4
        return packed

    def unpack (self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.exterimenter = _unpack("!L", raw, offset)
        offset = _skip(raw, offset, 4)
        assert offset - _offset == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_action_counter._MIN_LENGTH  # 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_action_base.__eq__(self, other): return False
        if self.exterimenter != other.counexterimenterter_id: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'action header: \n'
        outstr += ofp_action_base.show(self, prefix + '  ')
        outstr += prefix + 'exterimenter: ' + str(self.exterimenter) + '\n'
        return outstr
# --------------------------------------------------------------------------

# ---------------------------------------------------------------------
# OFInstruction
# ---------------------------------------------------------------------

@openflow_instruction("GOTO_TABLE", 1)
class ofp_instruction_goto_table(ofp_instruction_base):
    """Edit by CC, according to org.openflow.protocol.instruction.OFInstructionGotoTable
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8    # 16
    _MAX_LENGTH = ofp_instruction_base._MIN_LENGTH + 8 + ofp_match20._MIN_LENGTH * OFP_MAX_MATCH_FIELD_NUM  #80
    #_MIN_LENGTH = 16
    #_MAX_LENGTH = 80

    def __init__(self, **kw):
        self.next_table_id = 0     # 1 byte
        self.match_field_num = 0   # 1 byte
        self.packet_offset = 0     # 2 bytes
        self.match_list = []       # ofp_match20

        initHelper(self, kw)

    def pack(self):
        assert self._assert()
        
        packed = b""
        packed += ofp_instruction_base.pack(self)

        packed += struct.pack("!BBH", self.next_table_id,
            self.match_field_num, self.packet_offset)
        packed += _PAD4

        if len(self.match_list) == 0:
            packed += _PAD * ofp_match20._MIN_LENGTH * OFP_MAX_MATCH_FIELD_NUM
        elif len(self.match_list) > OFP_MAX_MATCH_FIELD_NUM:
            _log(error = "out of range in ofp_instruction_goto_table.match_list")   # FIXME: Raise Exception
        else:
            for match in self.match_list:
                packed += match.pack()
            packed += _PAD * (OFP_MAX_MATCH_FIELD_NUM - len(self.match_list)) * ofp_match20._MIN_LENGTH
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.next_table_id, self.match_field_num, self.packet_offset) = \
               _unpack('!BBH', raw, offset)
        offset = _skip(raw, offset, 4)
        for _ in xrange(self.match_field_num):
            match = ofp_match20()
            offset = match.unpack(raw, offset)
            self.match_list.append(match)
        offset = _skip(raw, offset, (OFP_MAX_MATCH_FIELD_NUM - len(self.match_list)) * ofp_match20._MIN_LENGTH)

        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_goto_table._MAX_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.next_table_id != other.next_table_id: return False
        if self.match_field_num != other.match_field_num: return False
        if self.packet_offset != other.packet_offset: return False
        if self.match_list != other.match_list: return False      # FIXME:
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'next_table_id:   ' + str(self.next_table_id) + '\n'
        outstr += prefix + 'match_field_num: ' + str(self.match_field_num) + '\n'
        outstr += prefix + 'packet_offset:   ' + str(self.packet_offset) + '\n'
        outstr += prefix + 'match_list: \n'
        for obj in self.match_list:
            outstr += obj.show(prefix + '  ')
        return outstr
    
@openflow_instruction("WRITE_METADATA", 2)
class ofp_instruction_write_metadata(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionWriteMetadata
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 4 + OFP_MAX_FIELD_LENGTH_IN_BYTE + 4   #32

    def __init__(self, **kw):
        self.metadata_offset = 0  # 2 bytes
        self.write_length = 0  # 2 bytes
        self.value = ''  # OFP_MAX_FIELD_LENGTH_IN_BYTE

        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        packed += struct.pack("!HH", self.metadata_offset, self.write_length)
        packed += Hex2Raw(self.value, OFP_MAX_FIELD_LENGTH_IN_BYTE).toRaw()
        packed += _PAD4
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.metadata_offset, self.write_length) = _unpack('!HH', raw, offset)
        offset, self.value = _readzs(raw, offset, OFP_MAX_FIELD_LENGTH_IN_BYTE)   # FIXME:?
        offset = _skip(raw, offset, 4)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_write_metadata._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.metadata_offset != other.metadata_offset: return False
        if self.write_length != other.write_length: return False
        if self.value != other.value: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'metadata_offset: ' + str(self.metadata_offset) + '\n'
        outstr += prefix + 'write_length:    ' + str(self.write_length) + '\n'
        outstr += prefix + 'value:           ' + self.value + '\n'
        return outstr

@openflow_instruction("WRITE_ACTIONS", 3)
class ofp_instruction_write_actions(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionWriteAction
    not defined yet
    """
    
    def __init__(self, **kw):
        initHelper(self, kw)
    
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_write_actions._MAX_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        return outstr
    
@openflow_instruction("APPLY_ACTIONS", 4)
class ofp_instruction_apply_actions(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionApplyAction
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8
    _MAX_LENGTH = ofp_instruction_base._MIN_LENGTH + 8 + OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION * ofp_action_base._MAX_LENGTH
    
    def __init__(self, **kw):
        self.action_num = 0    # 1 byte
        self.action_list = []  # ofp_action
        initHelper(self, kw)
    
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        
        packed += struct.pack("!B", self.action_num)
        packed += _PAD7
        if len(self.action_list) == 0:
            packed += _PAD * OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION * ofp_action_base._MAX_LENGTH
        elif self.action_num != len(self.action_list):
            _log(error="action_num !=" + str(len(self.action_list)))   # FIXME: Raise Exception
        elif self.action_num > OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION:
            _log(error="too much actions")      # FIXME: Raise Exception
        else:
            for action in self.action_list:
                packed += action.pack()
                packed += _PAD * (ofp_action_base._MAX_LENGTH - len(action))
            packed += _PAD * ofp_action_base._MAX_LENGTH * (OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION - self.action_num)
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        offset, self.action_num = _unpack('!B', raw, offset)
        offset = _skip(raw, offset, 7)
        offset, self.action_list = _unpack_actions(raw, OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION*ofp_action_base._MAX_LENGTH, offset, 1)  #FIXME:
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_apply_actions._MAX_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.action_num != other.action_num: return False
        if self.action_list != other.action_list: return False   #FIXME:
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'action_num: ' + str(self.action_num) + '\n'
        outstr += prefix + 'action_list: \n'
        for obj in self.action_list:
            outstr += obj.show(prefix + '  ')
        return outstr
    
@openflow_instruction("CLEAR_ACTIONS", 5)
class ofp_instruction_clear_actions(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionClearAction
    not defined yet
    """
    
    def __init__(self, **kw):
        initHelper(self, kw)
    
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_write_metadata._MAX_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        return outstr
    
@openflow_instruction("METER", 6)
class ofp_instruction_meter(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionMeter
    not defined yet
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8
    
    def __init__(self, **kw):
        self.meter_id = 0    # 1 byte
        initHelper(self, kw)
    
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        
        packed += struct.pack("!L", self.meter_id)
        packed += _PAD4
        
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, self.meter_id = _unpack('!L', raw, offset)
        offset = _skip(raw, offset, 4)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_meter._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.meter_id != other.meter_id: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'meter_id: ' + str(self.meter_id) + '\n'
        return outstr
    
@openflow_instruction("WRITE_METADATA_FROM_PACKET", 7)
class ofp_instruction_write_metadata_from_packet(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionWriteMetadataFromPacket
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8  #16

    def __init__(self, **kw):
        self.metadata_offset = 0  # 2 bytes
        self.write_length = 0  # 2 bytes
        self.packet_offset = 0 # 2 bytes

        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        packed += struct.pack("!HHH", self.metadata_offset, self.packet_offset, self.write_length)
        packed += _PAD2
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.metadata_offset, self.packet_offset, self.write_length) = _unpack('!HHH', raw, offset)
        offset = _skip(raw, offset, 2)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_write_metadata_from_packet._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.metadata_offset != other.metadata_offset: return False
        if self.packet_offset != other.packet_offset: return False
        if self.write_length != other.write_length: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'metadata_offset: ' + str(self.metadata_offset) + '\n'
        outstr += prefix + 'packet_offset: ' + str(self.packet_offset) + '\n'
        outstr += prefix + 'write_length:    ' + str(self.write_length) + '\n'
        return outstr
    
@openflow_instruction("GOTO_DIRECT_TABLE", 8)
class ofp_instruction_goto_direct_table(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionGotoDirectTable
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8 + ofp_match20._MIN_LENGTH    #24

    def __init__(self, **kw):
        self.next_table_id = 0     # 1 byte
        self.index_type = 0        # 1 byte, 0:value, 1:field
        self.packet_offset = 0     # 2 bytes
        self.index_value = 0       # 4 bytes
        self.index_field = None    # ofp_match20

        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        packed += struct.pack("!BBH", self.next_table_id, self.index_type, self.packet_offset)
        packed += _PAD4
        if self.index_type == 0:
            packed += struct.pack("!L", self.index_value)
            packed += _PAD4
        elif self.index_type == 1 and self.index_field != None:
            packed += self.index_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.next_table_id, self.index_type, self.packet_offset) = _unpack('!BBH', raw, offset)
        offset = _skip(raw, offset, 4)
        if self.index_type == 0:
            offset, (self.index_value,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.index_type == 1:
            self.index_field = ofp_match20()
            offset = self.index_field.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, ofp_match20._MIN_LENGTH)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_goto_direct_table._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.next_table_id != other.next_table_id: return False
        if self.index_type != other.index_type: return False
        if self.packet_offset != other.packet_offset: return False
        if self.index_value != other.index_value: return False
        if self.index_field != other.index_field: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'next_table_id: ' + str(self.next_table_id) + '\n'
        outstr += prefix + 'index_type:    ' + str(self.index_type) + '\n'
        outstr += prefix + 'packet_offset: ' + str(self.packet_offset) + '\n'
        if self.index_type == 0:
            outstr += prefix + 'index_value:   ' + str(self.index_value) + '\n'
        elif self.index_type == 1:
            outstr += prefix + 'index_field:   ' + str(self.index_field) + '\n'
        return outstr
    
@openflow_instruction("CONDITIONAL_JMP", 9)
class ofp_instruction_conditional_jmp(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionConditionJmp
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8 + 5 * ofp_match20._MIN_LENGTH    #24

    def __init__(self, **kw):
        
        self.offset1_direction = 0     # 1 byte, jump direction. 0: forward; 1:backward
        self.offset1_value_type = 0    # 1 byte
        self.offset2_direction = 0     # 1 byte
        self.offset2_value_type = 0    # 1 byte  //0 means to use value, 1 means to use field
        self.offset3_direction = 0     # 1 byte
        self.offset3_value_type = 0    # 1 byte
        self.field1 = None    #ofp_match20
        
        self.field2_value_type = 0     # 1 byte, compare field2, 0 means to use field2_value, 1 means to use field2
        self.field2_value = 0
        self.field2 = None    #ofp_match20
        
        self.offset1_value = 0
        self.offset1_field = None  #ofp_match20
        self.offset2_value = 0
        self.offset2_field = None  #ofp_match20
        self.offset3_value = 0
        self.offset3_field = None  #ofp_match20
        
        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        packed += struct.pack("!BBBBBBB", self.field2_value_type, self.offset1_direction, self.offset1_value_type,
                              self.offset2_direction, self.offset2_value_type, self.offset3_direction, self.offset3_value_type)
        packed += _PAD
        if self.field1 != None:
            packed += self.field1.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
            
        if self.field2_value_type == 0:
            packed += struct.pack("!L", self.field2_value)
            packed += _PAD4
        elif self.field2_value_type == 1 and self.field2 != None:
            packed += self.field2.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
            
        if self.offset1_value_type == 0:
            packed += struct.pack("!L", self.offset1_value)
            packed += _PAD4
        elif self.offset1_value_type == 1 and self.offset1_field != None:
            packed += self.offset1_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
            
        if self.offset2_value_type == 0:
            packed += struct.pack("!L", self.offset2_value)
            packed += _PAD4
        elif self.offset2_value_type == 1 and self.offset2_field != None:
            packed += self.offset2_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
            
        if self.offset3_value_type == 0:
            packed += struct.pack("!L", self.offset3_value)
            packed += _PAD4
        elif self.offset3_value_type == 1 and self.offset3_field != None:
            packed += self.offset3_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
            
        return packed
    
    def unpack(self, raw, offset=0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.field2_value_type, self.offset1_direction, self.offset1_value_type, self.offset2_direction, 
                 self.offset2_value_type, self.offset3_direction, self.offset3_value_type) = _unpack('!BBBBBBB', raw, offset)
        offset = _skip(raw, offset, 1)
        
        self.field1 = ofp_match20()
        offset = self.field1.unpack(raw, offset)
        
        if self.field2_value_type == 0:
            offset, (self.field2_value_type,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.field2_value_type == 1:
            self.field2 = ofp_match20()
            offset = self.field2.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, 8)
            
        if self.offset1_value_type == 0:
            offset, (self.offset1_value,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.offset1_value_type == 1:
            self.offset1_field = ofp_match20()
            offset = self.offset1_field.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, 8)
        
        if self.offset2_value_type == 0:
            offset, (self.offset2_value,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.offset2_value_type == 1:
            self.offset2_field = ofp_match20()
            offset = self.offset2_field.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, 8)
            
        if self.offset3_value_type == 0:
            offset, (self.offset3_value,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.offset3_value_type == 1:
            self.offset3_field = ofp_match20()
            offset = self.offset3_field.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, 8)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_conditional_jmp._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.field2_value_type != other.field2_value_type: return False
        if self.offset1_direction != other.offset1_direction: return False
        if self.offset1_value_type != other.offset1_value_type: return False
        if self.offset2_direction != other.offset2_direction: return False
        if self.offset2_value_type != other.offset2_value_type: return False
        if self.offset3_direction != other.offset3_direction: return False
        if self.offset3_value_type != other.offset3_value_type: return False
        if self.field1 != other.field1: return False
        if self.field2_value != other.field2_value: return False
        if self.field2 != other.field2: return False
        if self.offset1_value != other.offset1_value: return False
        if self.offset1_field != other.offset1_field: return False
        if self.offset2_value != other.offset2_value: return False
        if self.offset2_field != other.offset2_field: return False
        if self.offset3_value != other.offset3_value: return False
        if self.offset3_field != other.offset3_field: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'field2_value_type: ' + str(self.field2_value_type) + '\n'
        outstr += prefix + 'offset1_direction: ' + str(self.offset1_direction) + '\n'
        outstr += prefix + 'offset1_value_type:' + str(self.offset1_value_type) + '\n'
        outstr += prefix + 'offset2_direction: ' + str(self.offset2_direction) + '\n'
        outstr += prefix + 'offset2_value_type:' + str(self.offset2_value_type) + '\n'
        outstr += prefix + 'offset3_direction: ' + str(self.offset3_direction) + '\n'
        outstr += prefix + 'offset3_value_type:' + str(self.offset3_value_type) + '\n'
        outstr += prefix + 'field1:' + str(self.field1) + '\n'
        if self.field2_value_type == 0:
            outstr += prefix + 'field2_value: ' + str(self.field2_value) + '\n'
        elif self.field2_value_type == 1:
            outstr += prefix + 'field2:' + str(self.field2) + '\n'
        if self.offset1_value_type == 0:
            outstr += prefix + 'offset1_value: ' + str(self.offset1_value) + '\n'
        elif self.offset1_value_type == 1:
            outstr += prefix + 'offset1_field:' + str(self.offset1_field) + '\n'
        if self.offset2_value_type == 0:
            outstr += prefix + 'offset2_value: ' + str(self.offset2_value) + '\n'
        elif self.offset2_value_type == 1:
            outstr += prefix + 'offset2_field:' + str(self.offset2_field) + '\n'
        if self.offset3_value_type == 0:
            outstr += prefix + 'offset3_value: ' + str(self.offset3_value) + '\n'
        elif self.offset3_value_type == 1:
            outstr += prefix + 'offset3_field:' + str(self.offset3_field) + '\n'
        return outstr
    
@openflow_instruction("CALCULATE_FIELD", 10)
class ofp_instruction_calculate_field(ofp_instruction_base):
    """
    edit by CC
    according to org.openflow.protocol.instruction.OFInstructionCalculateField
    """
    _MIN_LENGTH = ofp_instruction_base._MIN_LENGTH + 8 + 2 * ofp_match20._MIN_LENGTH    #24

    def __init__(self, **kw):
        self.calc_type = 0             # 2 bytes, ofp_calc_type_map
        self.src_value_type = 0        # 1 byte, //0: use srcField_Value; 1: use srcField;
        self.des_field = None          # ofp_match20
        self.src_value = 0             # 4 bytes
        self.src_field = None          # ofp_match20

        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
        packed = b""
        packed += ofp_instruction_base.pack(self)
        
        packed += struct.pack("!HB", self.calc_type, self.src_value_type)
        packed += _PAD5
        if self.des_field != None:
            packed += self.des_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
        if self.src_value_type == 0:
            packed += struct.pack("!L", self.src_value)
            packed += _PAD4
        elif self.src_value_type == 1 and self.src_field != None:
            packed += self.src_field.pack()
        else:
            packed += _PAD * ofp_match20._MIN_LENGTH
        return packed
    
    def unpack(self, raw, offset = 0):
        _offset = offset
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.calc_type, self.src_value_type) = _unpack('!HB', raw, offset)
        offset = _skip(raw, offset, 5)
        
        self.des_field = ofp_match20()
        offset = self.des_field.unpack(raw, offset)
        
        if self.src_value_type == 0:
            offset, (self.src_value,) = _unpack('!L', raw, offset)
            offset = _skip(raw, offset, 4)
        elif self.src_value_type == 1:
            self.src_field = ofp_match20()
            offset = self.src_field.unpack(raw, offset)
        else:
            offset = _skip(raw, offset, 8)
        
        assert offset - _offset == len(self)
        return offset, length

    @staticmethod
    def __len__():
        return ofp_instruction_calculate_field._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_instruction_base.__eq__(self, other): return False
        if self.calc_type != other.calc_type: return False
        if self.src_value_type != other.src_value_type: return False
        if self.des_field != other.des_field: return False
        if self.src_value != other.src_value: return False
        if self.src_field != other.src_field: return False
        return True

    def show(self, prefix=''):
        outstr = ''
        outstr += prefix + 'instruction header: \n'
        outstr += ofp_instruction_base.show(self, prefix + '  ')
        outstr += prefix + 'calc_type: ' + str(self.calc_type) + '\n'
        outstr += prefix + 'src_value_type:    ' + str(self.src_value_type) + '\n'
        outstr += prefix + 'des_field: ' + str(self.des_field) + '\n'
        if self.src_value_type == 0:
            outstr += prefix + 'src_value:   ' + str(self.src_value) + '\n'
        elif self.src_value_type == 1:
            outstr += prefix + 'src_field:   ' + str(self.src_field) + '\n'
        return outstr
# --------------------------------------------------------------------

# 3. Controller-to-Switch Messages

@openflow_sc_message("OFPT_HELLO", 0)
class ofp_hello (ofp_header):
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        return outstr

@openflow_s_message("OFPT_ERROR", 1)
class ofp_error (ofp_header):
    _MIN_LENGTH = ofp_header._MIN_LENGTH + 16   # 
    _MAX_LENGTH = ofp_header._MIN_LENGTH + 16 + OFP_ERROR_STRING_MAX_LENGTH  #280
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.type = 0         # 2 bytes, ofp_error_type
        self.code = 0         # 2 bytes
        self.device_id = 0    # 4 bytes
        self.slot_id = 0      # 2 bytes
        self.experimenter = 0 # 4 bytes
        self.experimenter_error_type = 0  # 4 bytes
        self.experimenter_error_code = 0  # 2 bytes
        self.data = b''  # 256 bytes
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!HHLH", self.type, self.code, self.device_id, self.slot_id)
        packed += _PAD6
        packed += self.data
        packed += _PAD * (OFP_ERROR_STRING_MAX_LENGTH - len(self.data))   # FIXME:
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        offset, (self.type, self.code, self.device_id, self.slot_id) = _unpack("!HHLH", raw, offset)
        offset = _skip(raw, offset, 6)
        offset, self.data = _read(raw, offset, OFP_ERROR_STRING_MAX_LENGTH)
        
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return ofp_error._MAX_LENGTH

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.type != other.type: return False
        if self.code != other.code: return False
        if self.device_id != other.device_id: return False
        if self.slot_id != other.slot_id: return False
        if self.data != other.data: return False
        return True

    def show (self, prefix=''):   # FIXME:
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        t = self.type
        c = self.code
        if t < len(ofp_error_type):
            n = ofp_error_type_map[t]
            t = "%s (%i)" % (n, t)
            n = 'ofp' + n.lower()[5:] + '_code_map'
            if n in sys.modules[__name__].__dict__:
                if c in sys.modules[__name__].__dict__[n]:
                    c = "%s (%i)" % (sys.modules[__name__].__dict__[n][c], c)
        outstr += prefix + 'type:      ' + str(t) + '\n'
        outstr += prefix + 'code:      ' + str(c) + '\n'
        outstr += prefix + 'device_id: ' + str(self.device_id) + '\n'
        if len(self.data):
            outstr += prefix + 'datalen: %s\n' % (len(self.data),)
            outstr += prefix + hexdump(self.data).replace("\n", "\n" + prefix)
        return outstr.strip()
    
@openflow_sc_message("OFPT_ECHO_REQUEST", 2,
    request_for="ofp_echo_reply")
class ofp_echo_request (ofp_header):
    _MIN_LENGTH = 8
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.body = b''
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.body
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, self.body = _read(raw, offset, length - 8)
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return 8 + len(self.body)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.body != other.body: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'body:\n'
        outstr += _format_body(self.body, prefix + '  ') + '\n'
        return outstr


@openflow_sc_message("OFPT_ECHO_REPLY", 3,
    reply_to="ofp_echo_request")
class ofp_echo_reply (ofp_header):
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.body = b''
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.body
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, self.body = _read(raw, offset, length - 8)
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return 8 + len(self.body)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.body != other.body: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'body:\n'
        outstr += _format_body(self.body, prefix + '  ') + '\n'
        return outstr

@openflow_sc_message("OFPT_EXPERIMENTER", 4)
class ofp_experimenter (ofp_header):
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.experimenter = 0                  # 4 bytes
        self.experimenter_data = None          # OFExperimenterData, not defined
        self.experimenter_data_factory = None  # OFExperimenterDataFactory, not defined
        
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!L", self.experimenter)
        
        
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, self.experimenter = _unpack("!L", raw, offset)
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return 12 + len(self.experimenter_data)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.experimenter != other.experimenter: return False
        if self.experimenter_data != self.experimenter_data: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'experimenter: ' + str(self.experimenter) + '\n'
        return outstr
    
@openflow_c_message("OFPT_FEATURES_REQUEST", 5,
    request_for="ofp_features_reply")
class ofp_features_request (ofp_header):
    def __init__ (self, **kw):
        ofp_header.__init__(self)
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        return outstr
    
@openflow_s_message("OFPT_FEATURES_REPLY", 6,
    reply_to="ofp_features_request")
class ofp_features_reply (ofp_header):
    """
    modified by CC, done
    """
    _MIN_LENGTH = 16 + 3 * OFP_NAME_MAX_LENGTH + ofp_header._MIN_LENGTH
    #_MIN_LENGTH = 216
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.device_id = 0              # 4 bytes
        self.slot_id = 0                # 2 bytes
        self.port_num = 0               # 2 bytes
        self.table_num = 0              # 2 bytes
        self.capabilities = 0           # 4 bytes
        self.experimenter_name = b""    # 64 bytes
        self.device_forward_engine_name = b""          # 64 bytes
        self.device_lookup_engine_name = b""        # 64 bytes
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!LHHH", self.device_id, self.slot_id, self.port_num, 
            self.table_num)
        packed += _PAD2
        packed += struct.pack("!L",self.capabilities)
        packed += self.experimenter_name.ljust(OFP_NAME_MAX_LENGTH,'\0')
        packed += self.device_forward_engine_name.ljust(OFP_NAME_MAX_LENGTH,'\0')
        packed += self.device_lookup_engine_name.ljust(OFP_NAME_MAX_LENGTH,'\0')
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        offset,(self.device_id, self.slot_id, self.port_num, self.table_num) = \
            _unpack("!LHHH", raw, offset)
        offset = _skip(raw, offset, 2)
        offset,(self.capabilities,) = _unpack("!L",raw,offset)
        offset,self.experimenter_name = _readzs(raw, offset, OFP_NAME_MAX_LENGTH)
        offset,self.device_forward_engine_name = _readzs(raw, offset, OFP_NAME_MAX_LENGTH)
        offset,self.device_lookup_engine_name = _readzs(raw, offset, OFP_NAME_MAX_LENGTH)
        assert length == len(self)
        return offset,length

    def __len__ (self):
        return ofp_features_reply._MIN_LENGTH
        #return 216

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.device_id != other.device_id: return False
        if self.slot_id != other.slot_id: return False
        if self.port_num != other.port_num: return False
        if self.table_num != other.table_num: return False
        if self.capabilities != other.capabilities: return False
        if self.experimenter_name != other.experimenter_name: return False
        if self.device_forward_engine_name != other.device_forward_engine_name: return False
        if self.device_lookup_engine_name != other.device_lookup_engine_name: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'device_id:                  ' + str(self.device_id) + '\n'
        outstr += prefix + 'slot_id:                    ' + str(self.slot_id) + '\n'
        outstr += prefix + 'port_num:                   ' + str(self.port_num) + '\n'
        outstr += prefix + 'table_num:                  ' + str(self.table_num) + '\n'
        outstr += prefix + 'capabilities:               ' + str(self.capabilities) + '\n'
        outstr += prefix + 'experimenter_name:          ' + self.experimenter_name + '\n'
        outstr += prefix + 'device_forward_engine_name: ' + self.device_forward_engine_name + '\n'
        outstr += prefix + 'device_lookup_engine_name:  ' + self.device_lookup_engine_name + '\n'
        return outstr
    
@openflow_c_message("OFPT_GET_CONFIG_REQUEST", 7,  # added by cc
    request_for="ofp_get_config_reply")
class ofp_get_config_request (ofp_header):
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        return outstr
    
@openflow_s_message("OFPT_GET_CONFIG_REPLY", 8,  # added by cc
    reply_to="ofp_get_config_request")
class ofp_get_config_reply (ofp_header):  # uses ofp_switch_config
    _MIN_LENGTH = 16
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.device_id = 0     # 4 bytes
        self.flags = 0         # 2 bytes
        self.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN   #128
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!LHH", self.device_id, self.flags, self.miss_send_len)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        offset,(self.device_id, self.flags, self.miss_send_len) = \
            _unpack("!LHH", raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 16

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.device_id != other.device_id: return False
        if self.flags != other.flags: return False
        if self.miss_send_len != other.miss_send_len: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'flags:         ' + str(self.flags) + '\n'
        outstr += prefix + 'miss_send_len: ' + str(self.miss_send_len) + '\n'
        return outstr


@openflow_c_message("OFPT_SET_CONFIG", 9)  # changed by cc
class ofp_set_config (ofp_header):  # uses ofp_switch_config
    _MIN_LENGTH = 12
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.flags = 0
        self.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN  # 128
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!HH", self.flags, self.miss_send_len)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, (self.flags, self.miss_send_len) = _unpack("!HH", raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 12

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.flags != other.flags: return False
        if self.miss_send_len != other.miss_send_len: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'flags:         ' + str(self.flags) + '\n'
        outstr += prefix + 'miss_send_len: ' + str(self.miss_send_len) + '\n'
        return outstr
    
@openflow_s_message("OFPT_PACKET_IN", 10)  # FIXME:
class ofp_packet_in (ofp_header):
    _MIN_LENGTH = 32
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.buffer_id = NO_BUFFER  # 4 bytes
        self.total_len = 0  # 2 bytes
        self.reason = 0  # 1 bytes, ofp_packet_in_reason_rev_map
        self.table_id = 0  # 1 bytes
        self.cookie = 0  # 8 bytes
        self.device_id = 0  # 4 bytes
        #self.slot_id = 0  # 2 bytes
        #self.port_id = 0  # 2 bytes
        self.slot_port_id = 0  #4 bytes
        self.data = None  # bytes[2048]
        
        initHelper(self, kw)

    def _validate (self):
        if self.data and (self.total_len < len(self.data)):
            return "total len less than data len"

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        """
        packed += struct.pack("!LHBBQLHH", self.buffer_id, self.total_len, self.in_port,
            self.reason, self.cookie, self.device_id, self.slot_id, self.port_id)
        """
        packed += struct.pack("!LHBBQLL", self.buffer_id, self.total_len, self.in_port,
            self.reason, self.cookie, self.device_id, self.slot_port_id)
        packed += self.data
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        """
        offset, (self.buffer_id, self._total_len, self.reason, self.table_id, self.cookie,
            self.device_id, self.slot_id, self.port_id) = _unpack("!LHBBQLHH", raw, offset)
        """
        offset, (self.buffer_id, self._total_len, self.reason, self.table_id, self.cookie,
            self.device_id, self.slot_port_id) = _unpack("!LHBBQLL", raw, offset)
        offset, self.data = _read(raw, offset, length - 32)
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return 32 + len(self.data)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.buffer_id != other.buffer_id: return False
        if self.total_len != other.total_len: return False
        if self.reason != other.reason: return False
        if self.table_id != other.table_id: return False
        if self.cookie != other.cookie: return False
        if self.device_id != other.device_id: return False
        #if self.slot_id != other.slot_id: return False
        #if self.port_id != other.port_id: return False
        if self.slot_port_id != other.slot_port_id: return False
        if self.data != other.data: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
        outstr += prefix + 'total_len: ' + str(self._total_len) + '\n'  # FIXME: total_len
        outstr += prefix + 'reason:    ' + str(self.reason) + '\n'
        outstr += prefix + 'table_id:  ' + str(self.table_id) + '\n'
        outstr += prefix + 'cookie:    ' + str(self.cookie) + '\n'
        outstr += prefix + 'device_id: ' + str(self.device_id) + '\n'
        #outstr += prefix + 'slot_id:   ' + str(self.slot_id) + '\n'
        #outstr += prefix + 'port_id:   ' + str(self.port_id) + '\n'
        outstr += prefix + 'slot_port_id:   ' + str(self.slot_port_id) + '\n'
        outstr += prefix + 'data: ' + str(self.data) + '\n'
        return outstr
    
@openflow_c_message("OFPT_FLOW_REMOVED", 11)  # changed by cc
class ofp_flow_removed (ofp_header):
    _MIN_LENGTH = 88
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)  
        self.match = None  # ofp_match
        self.cookie = 0  # 8 bytes
        self.priority = 0  # 2 bytes
        self.reason = 0  # 1 byte, ofp_flow_removed_reason
        self.duration_sec = 0  # 4 bytes
        self.duration_nsec = 0  # 4 bytes
        self.idle_timeout = 0  # 2 bytes
        self.packet_count = 0  # 8 bytes
        self.byte_count = 0  # 8 bytes

        initHelper(self, kw)

    def _validate (self):
        if not isinstance(self.match, ofp_match):
            return "match is not class ofp_match"
        return None

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.match.pack()
        packed += struct.pack("!QHB", self.cookie, self.priority, self.reason)
        packed += _PAD
        packed += struct.pack("!LLH", self.duration_sec, self.duration_nsec,
                              self.idle_timeout)
        packed += _PAD2
        packed += struct.pack("!QQ", self.packet_count, self.byte_count)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        self.match = ofp_match()
        offset = self.match.unpack(raw, offset)
        offset, (self.cookie, self.priority, self.reason) = \
            _unpack("!QHB", raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.duration_sec, self.duration_nsec, self.idle_timeout) = \
            _unpack("!LLH", raw, offset)
        offset = _skip(raw, offset, 2)
        offset, (self.packet_count, self.byte_count) = \
            _unpack("!QQ", raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 88

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.match != other.match: return False
        if self.cookie != other.cookie: return False
        if self.priority != other.priority: return False
        if self.reason != other.reason: return False
        if self.duration_sec != other.duration_sec: return False
        if self.duration_nsec != other.duration_nsec: return False
        if self.idle_timeout != other.idle_timeout: return False
        if self.packet_count != other.packet_count: return False
        if self.byte_count != other.byte_count: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'match: \n'
        outstr += self.match.show(prefix + '  ')
        outstr += prefix + 'cookie:        ' + str(self.cookie) + '\n'
        outstr += prefix + 'priority:      ' + str(self.priority) + '\n'
        outstr += prefix + 'reason:        ' + str(self.reason) + '\n'
        outstr += prefix + 'duration_sec:  ' + str(self.duration_sec) + '\n'
        outstr += prefix + 'duration_nsec: ' + str(self.duration_nsec) + '\n'
        outstr += prefix + 'idle_timeout:  ' + str(self.idle_timeout) + '\n'
        outstr += prefix + 'packet_count:  ' + str(self.packet_count) + '\n'
        outstr += prefix + 'byte_count:    ' + str(self.byte_count) + '\n'
        return outstr
    
@openflow_s_message("OFPT_PORT_STATUS", 12)
class ofp_port_status (ofp_header):
    _MIN_LENGTH = 136
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.reason = 0  # 1 bytes, ofp_port_reason_rev_map
        self.desc = None  # ofp_phy_port
    
        initHelper(self, kw)

    def _validate (self):
        if not isinstance(self.desc, ofp_phy_port):
            return "desc is not class ofp_phy_port"
        return None

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!B", self.reason)
        packed += _PAD * 7
        packed += self.desc.pack()
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, (self.reason,) = _unpack("!B", raw, offset)
        offset = _skip(raw, offset, 7)
        self.desc = ofp_phy_port()
        offset = self.desc.unpack(raw, offset)
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 136

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.reason != other.reason: return False
        if self.desc != other.desc: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'reason: ' + str(self.reason) + '\n'
        outstr += prefix + 'desc: \n'
        outstr += self.desc.show(prefix + '  ')
        return outstr
    
    
@openflow_s_message("OFPT_RESOURCE_REPORT", 13)
class ofp_resource_report (ofp_header):
    # _MIN_LENGTH = ofp_header._MIN_LENGTH + 16
    # _MAX_LENGTH = ofp_flow_table_resource._MIN_LENGTH + ofp_table_resource._MIN_LENGTH * OF_MAX_TABLE_TYPE
    _MIN_LENGTH = 24
    _MAX_LENGTH = 88

    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.resource_type = 0  # 1 byte, ofp_resource_report_type_rev_map
        self.slot_id = 0       # 2 bytes
        self.counter_num = 0   # 4 bytes
        self.meter_num = 0     # 4 bytes
        self.group_num = 0     # 4 bytes
        self.table_resources_map = {}  # <OFTableType, OFTableResource>
        
        initHelper(self, kw)
        
    def pack(self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!B", self.resource_type)
        packed += _PAD
        packed += struct.pack("!HLLL", self.slot_id, self.counter_num, self.meter_num, self.group_num)
        for i in range(OF_MAX_TABLE_TYPE):
            packed += self.table_resources_map[i].pack()
        return packed
    
    def unpack(self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, (self.resource_type,) = _unpack("!B", raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.slot_id, self.counter_num, self.meter_num, self.group_num) = _unpack("!HLLL", raw, offset)
        for i in range(OF_MAX_TABLE_TYPE):
            table_resource = ofp_table_resource()
            offset = table_resource.unpack(raw, offset)
            self.table_resources_map[i] = table_resource
        assert length == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return 88
    
    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.resource_type != other.resource_type: return False
        if self.slot_id != other.slot_id: return False
        if self.counter_num != other.counter_num: return False
        if self.meter_num != other.meter_num: return False
        if self.group_num != other.group_num: return False
        if self.table_resources_map != other.table_resources_map: return False
        return True
    
    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'resource_type: ' + str(self.resource_type) + '\n'
        outstr += prefix + 'slot_id:      ' + str(self.slot_id) + '\n'
        outstr += prefix + 'counter_num:  ' + str(self.counter_num) + '\n'
        outstr += prefix + 'meter_num:    ' + str(self.meter_num) + '\n'
        outstr += prefix + 'group_num:    ' + str(self.group_num) + '\n'
        for i in xrange(OF_MAX_TABLE_TYPE):
            outstr += prefix + 'pof_table_resouce_desc' + str(i) + '\n'
            outstr += self.table_resources_map[i].show(prefix + '   ')
        return outstr
    
# @openflow_c_message("OFPT_PACKET_OUT", 14)  # FIXME:
# class ofp_packet_out (ofp_header):
#     _MIN_LENGTH = 16
#     def __init__ (self, **kw):
#         ofp_header.__init__(self)
#         self._buffer_id = NO_BUFFER
#         self.in_port = OFPP_NONE
#         self.actions = []
#         self._data = b''
#     
#         # ofp_flow_mod & ofp_packet_out do some special handling of 'actions'
#     
#         # Allow "action" as a synonym for "actions"
#         if 'action' in kw and 'actions' not in kw:
#             kw['actions'] = kw['action']
#             del kw['action']
#         initHelper(self, kw)
#     
#         # Allow use of actions=<a single action> for kw args.
#         if not hasattr(self.actions, '__getitem__'):
#             self.actions = [self.actions]
# 
#     @property
#     def buffer_id (self):
#         if self._buffer_id == NO_BUFFER: return None
#         return self._buffer_id
#     @buffer_id.setter
#     def buffer_id (self, val):
#         if val is None: val = NO_BUFFER
#         self._buffer_id = val
# 
#     @property
#     def data (self):
#         return self._data
#     @data.setter
#     def data (self, data):
#         if data is None:
#             self._data = b''
#         elif isinstance(data, packet_base):
#             self._data = data.pack()
#         elif isinstance(data, ofp_packet_in):
#             # Enable you to easily resend a packet
#             self._data = b''
#             self.buffer_id = data.buffer_id
#             if self.buffer_id is None:
#                 # TODO: It'd be nice to log and then ignore if data is incomplete
#                 #      Unfortunately, we currently have no logging in here, so we
#                 #      assert instead which is a either too drastic or too quiet.
#                 assert data.is_complete
#                 self._data = data._data
#             self.in_port = data.in_port
#         elif isinstance(data, bytes):
#             self._data = data
#         assert assert_type("data", self._data, (bytes,))
# 
#     def _validate (self):
#         if self.buffer_id is not None and self.data != b'':
#             return "can not have both buffer_id and data set"
#         return None
# 
#     def pack (self):
#         assert self._assert()
#     
#         actions = b''.join((i.pack() for i in self.actions))
#         actions_len = len(actions)
#     
#         if self.data is not None:
#             return b''.join((ofp_header.pack(self),
#                 struct.pack("!LHH", self._buffer_id, self.in_port, actions_len),
#                 actions, self.data))
#         else:
#             return b''.join((ofp_header.pack(self),
#                 struct.pack("!LHH", self._buffer_id, self.in_port, actions_len),
#                 actions))
# 
#     def unpack (self, raw, offset=0):
#         _offset = offset
#         offset, length = self._unpack_header(raw, offset)
#         offset, (self._buffer_id, self.in_port, actions_len) = \
#             _unpack("!LHH", raw, offset)
#         offset, self.actions = _unpack_actions(raw, actions_len, offset)
#     
#         remaining = length - (offset - _offset)
#         if remaining <= 0:
#             self.data = None
#         else:
#             offset, self.data = _read(raw, offset, remaining)
#     
#         assert length == len(self)
#         return offset, length
# 
#     def __len__ (self):
#         return 16 + reduce(operator.add, (len(a) for a in self.actions),
#             0) + (len(self.data) if self.data else 0)
# 
#     def __eq__ (self, other):
#         if type(self) != type(other): return False
#         if not ofp_header.__eq__(self, other): return False
#         if self.buffer_id != other.buffer_id: return False
#         if self.in_port != other.in_port: return False
#         if self.actions != other.actions: return False
#         return True
# 
#     def show (self, prefix=''):
#         outstr = ''
#         outstr += prefix + 'header: \n'
#         outstr += ofp_header.show(self, prefix + '  ')
#         outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
#         outstr += prefix + 'in_port: ' + str(self.in_port) + '\n'
#         outstr += prefix + 'actions_len: ' + str(len(self.actions)) + '\n'
#         outstr += prefix + 'actions: \n'
#         for obj in self.actions:
#             if obj is None:
#                 raise RuntimeError("An element of self.actions was None! "
#                                + "Bad formatting...")
#             outstr += obj.show(prefix + '  ')
#         return outstr

@openflow_c_message("OFPT_PACKET_OUT", 14)
class ofp_packet_out (ofp_header): #change to avoid collision by milktank
    _MIN_LENGTH = 16
    _MAX_LENGTH = 2360
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self._buffer_id = NO_BUFFER
        self.in_port = OFPP_ANY
        #self.actionsLength = 0
        self.actions = []
        self._data = b''

        # ofp_flow_mod & ofp_packet_out do some special handling of 'actions'

        # Allow "action" as a synonym for "actions"
        if 'action' in kw and 'actions' not in kw:
            kw['actions'] = kw['action']
            del kw['action']
        initHelper(self, kw)

    # Allow use of actions=<a single action> for kw args.
        if not hasattr(self.actions, '__getitem__'):
            self.actions = [self.actions]
      
#         self.actionsLength = len(self.actions)   #added by lsr
  
    @property
    def buffer_id (self):
        if self._buffer_id == NO_BUFFER: return None
        return self._buffer_id
    @buffer_id.setter
    def buffer_id (self, val):
        if val is None: val = NO_BUFFER
        self._buffer_id = val

    @property
    def data (self):
        return self._data
    @data.setter
    def data (self, data):

        if data is None:
            self._data = b''
        elif isinstance(data, packet_base):
            self._data = data.pack()
        elif isinstance(data, ofp_packet_in):
            # Enable you to easily resend a packet
            self._data = b''
            self.buffer_id = data.buffer_id
            if self.buffer_id is None:
            #TODO: It'd be nice to log and then ignore if data is incomplete
            #      Unfortunately, we currently have no logging in here, so we
            #      assert instead which is a either too drastic or too quiet.
            #assert data.is_complete  change by milktank
                self._data = data.data
            self.in_port = data.slot_port_id 
        elif isinstance(data, bytes):
            self._data = data
        assert assert_type("data", self._data, (bytes,))

    def _validate (self):
        if self.buffer_id is not None and self.data != b'':
            return "can not have both buffer_id and data set"
        return None
      
    def pack (self):
        assert self._assert()

        actions = b''.join((i.pack() for i in self.actions))
        actions_len = len(actions)
        packed=b""
    
        packed += ofp_header.pack(self)
        packed += struct.pack("!L" ,self._buffer_id)
        packed += struct.pack("!L" ,self.in_port)
        packed += struct.pack("!B" ,len(self.actions))
        packed += _PAD*3
        packed += struct.pack("!L" ,len(self.data))
        #print ("\n")
        #print (packed.encode("hex"))
#         print "data:", self.data
#         print "_data:", self._data
#     
        if len(self.actions)==0:
            packed += _PAD * OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION * ofp_action_base._MAX_LENGTH
        else:
            numcount = 0
            for i in self.actions:
                packed += i.pack()
                if len(i)< ofp_action_base._MAX_LENGTH:
                    packed += _PAD * (ofp_action_base._MAX_LENGTH-len(i))
                numcount+=1
            #print (packed.encode("hex"))
            if numcount < OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION:
                packed +=_PAD * (OFP_MAX_ACTION_NUMBER_PER_INSTRUCTION - numcount) *ofp_action_base._MAX_LENGTH
            #print (packed.encode("hex"))
            if (self.data !=b""):
                if (len(self.data) < OFP_PACKET_IN_MAX_LENGTH):
                    #datapacked =b""+ struct.pack("!10s" ,self.data)
                    #print ("datapacked:",datapacked.encode("hex"))    
                    packed += self.data
                    #print ("data:",self.data.encode("hex"))
                    #print (len(self.data))
            #print ("Blank:",(_PAD*(OFP_PACKET_IN_MAX_LENGTH - len(self.data))).encode("hex"))
            #print ("Blank:",(_PAD*1600).encode("hex"))
            blank=OFP_PACKET_IN_MAX_LENGTH - len(self.data)
            #print ("before memset blank:\n",packed.encode("hex"))
            if blank > 1024:            
                packed += _PAD*(1024)
                packed += _PAD*(blank-1024)
                #print ("Blank1:\n",(_PAD*(1024)).encode("hex"))
                #print ("Blank2:\n",( _PAD*(blank-1024)).encode("hex"))
            else:
                packed += _PAD*blank
            #print ("after memset blank:\n",packed.encode("hex"))    
            #print ("after memset blank length:\n",len(packed))            
        return packed
        """
        if self.data is not None:
            return b''.join((ofp_header.pack(self),
                struct.pack("!LHH", self._buffer_id, self.in_port, actions_len),
                actions, self.data))
        else:
            return b''.join((ofp_header.pack(self),
                struct.pack("!LHH", self._buffer_id, self.in_port, actions_len),
                actions))
        """
    

    def unpack (self, raw, offset=0):
        _offset = offset
        offset,length = self._unpack_header(raw, offset)
        offset,(self._buffer_id, self.in_port, actions_len) = \
            _unpack("!LHH", raw, offset)
        offset,self.actions = _unpack_actions(raw, length - 24, offset, 0)

        remaining = length - (offset - _offset)
        if remaining <= 0:
            self.data = None
        else:
            offset,self.data = _read(raw, offset, remaining)

        assert length == len(self)
        return offset,length

    def __len__ (self):
        return self._MAX_LENGTH  
        #return 16 + reduce(operator.add, (len(a) for a in self.actions),
            #0) + (len(self.data) if self.data else 0)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.buffer_id != other.buffer_id: return False
        if self.in_port != other.in_port: return False
        if self.actions != other.actions: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'buffer_id: ' + str(self.buffer_id) + '\n'
        outstr += prefix + 'in_port: ' + str(self.in_port) + '\n'
        outstr += prefix + 'actions_len: ' + str(len(self.actions)) + '\n'
        outstr += prefix + 'actions: \n'
        for obj in self.actions:
            if obj is None:
                raise RuntimeError("An element of self.actions was None! "
                                 + "Bad formatting...")
            outstr += obj.show(prefix + '  ')
        return outstr
  
@openflow_c_message("OFPT_FLOW_MOD", 15)
class ofp_flow_mod (ofp_header):
    _MIN_LENGTH = 48
    _MAX_LENGTH = 48 + ofp_matchx._MIN_LENGTH * OFP_MAX_MATCH_FIELD_NUM + \
                    ofp_instruction_base._MAX_LENGTH * OFP_MAX_INSTRUCTION_NUM  # 2192
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.command = 0          # 1 byte, ofp_flow_mod_command
        self.match_field_num = 0  # 1 byte
        self.instruction_num = 0  # 1 byte
        self.counter_id = 0       # 4 bytes
        self.cookie = 0           # 8 bytes
        self.cookie_mask = 0      # 8 bytes
        self.table_id = 0         # 1 byte
        self.table_type = 0       # ofp_table_type
        self.idle_timeout = 0     # 2 bytes
        self.hard_timeout = 0     # 2 bytes
        self.priority = OFP_DEFAULT_PRIORITY  # 2 bytes
        self.index = 0            # 4 bytes
        self.match_list = []      # ofp_matchx
        self.instruction_list = []  # ofp_instruction
        
        initHelper(self, kw)

    def _validate (self):
        """
        if not isinstance(self.match, ofp_match):
            return "match is not class ofp_match"
        """
        # FIXME:
        return None

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack ("!BBB" , self.command, self.match_field_num, self.instruction_num)
        packed += _PAD
        packed += struct.pack ("!LQQBBHHHL", self.counter_id, self.cookie, self.cookie_mask,
                               self.table_id, self.table_type, self.idle_timeout,
                               self.hard_timeout, self.priority, self.index)
        packed += _PAD4
        
        for i in self.match_list:
            packed += i.pack()
        if (len(self.match_list) < OFP_MAX_MATCH_FIELD_NUM):
            packed += _PAD * ((OFP_MAX_MATCH_FIELD_NUM - len(self.match_list)) * ofp_matchx._MIN_LENGTH)
            
        for i in self.instruction_list:
            packed += i.pack()
            if (len(i) < ofp_instruction_base._MAX_LENGTH):
                packed += _PAD * (ofp_instruction_base._MAX_LENGTH - len(i))
        if (len(self.instruction_list) < OFP_MAX_INSTRUCTION_NUM):
            packed += _PAD * ((OFP_MAX_INSTRUCTION_NUM - len(self.instruction_list)) * ofp_instruction_base._MAX_LENGTH)
        return packed

    def unpack (self, raw, offset=0):  # FIXME:
        offset, length = self._unpack_header(raw, offset)
        offset, (self.command, self.match_field_num, self.instruction_num) = \
            _unpack("!BBB", raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.counter_id, self.cookie, self.cookie_mask, self.table_id,
                self.table_type, self.idle_timeout, self.hard_timeout,
                self.priority, self.index) = _unpack("!LQQBBHHHL", raw, offset)
        self.match_list = []
        self.instruction_list = []
        for _ in xrange(OFP_MAX_MATCH_FIELD_NUM):
            matchx = ofp_matchx()
            offset = matchx.unpack(raw, offset)
            self.match_list.append(matchx)
            
        instructions_len = ofp_instruction_base._MAX_LENGTH * OFP_MAX_INSTRUCTION_NUM
        offset, self.instruction_list = _unpack_instructions(raw, instructions_len, offset)
        
        assert length == len(self)
        return offset, length

    def __len__ (self):
        return ofp_flow_mod._MAX_LENGTH

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.command != other.command: return False
        if self.match_field_num != other.match_field_num: return False
        if self.instruction_num != other.instruction_num: return False
        if self.counter_id != other.counter_id: return False
        if self.cookie != other.cookie: return False
        if self.table_id != other.table_id: return False
        if self.table_type != other.table_type: return False
        if self.idle_timeout != other.idle_timeout: return False
        if self.hard_timeout != other.hard_timeout: return False
        if self.priority != other.priority: return False
        if self.index != other.index: return False
        if self.match_list != other.match_list: return False
        if self.instruction_list != other.instruction_list: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'command:         ' + str(self.command)
        outstr += ' (' + ofp_table_mod_cmd_map.get(self.command, "Unknown") + ')\n' 
        outstr += prefix + 'match_field_num: ' + str(self.match_field_num) + '\n'
        outstr += prefix + 'instruction_num: ' + str(self.instruction_num) + '\n'
        outstr += prefix + 'counter_id:      ' + str(self.counter_id) + '\n'
        outstr += prefix + 'cookie:          ' + str(self.cookie) + '\n'
        outstr += prefix + 'table_id:        ' + str(self.table_id) + '\n'
        outstr += prefix + 'table_type:      ' + str(self.table_type)
        outstr += ' (' + ofp_table_type_map.get(self.table_type, "Unknown") + ')\n'
        outstr += prefix + 'idle_timeout:    ' + str(self.idle_timeout) + '\n'
        outstr += prefix + 'hard_timeout:    ' + str(self.hard_timeout) + '\n'
        outstr += prefix + 'priority:        ' + str(self.priority) + '\n'
        outstr += prefix + 'index:           ' + str(self.index) + '\n'
        outstr += prefix + 'match_list: \n'
        for obj in self.match_list:
            outstr += obj.show(prefix + '  ')
        outstr += prefix + 'instruction_list: \n'
        for obj in self.instruction_list:
            outstr += obj.show(prefix + '  ')
        return outstr
    
@openflow_c_message("OFPT_GROUP_MOD", 16)
class ofp_group_mod (ofp_header):
    _MIN_LENGTH = ofp_header._MIN_LENGTH + 16
    _MAX_LENGTH = ofp_header._MIN_LENGTH + 16 + OFP_MAX_ACTION_NUMBER_PER_GROUP * ofp_action_base._MAX_LENGTH

    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.command = 0      # 1 byte, ofp_group_mod_command
        self.group_type = 0   # 1 byte, ofp_group_typy
        self.action_num = 0   # 1 byte
        self.group_id = 0     # 4 bytes
        self.counter_id = 0    # 4 bytes
        self.action_list = []  # ofp_action

        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!BBB", self.command, self.group_type, self.action_num)
        packed += _PAD
        packed += struct.pack("LL", self.group_id, self.counter_id)
        packed += _PAD4
        for action in self.action_list:
            packed += action.pack()
            packed += _PAD * (ofp_action_base._MAX_LENGTH - len(action))
        packed += _PAD * (OFP_MAX_ACTION_NUMBER_PER_GROUP - self.action_num) * ofp_action_base._MAX_LENGTH
        return packed
    
    def unpack (self, raw, offset=0):  # FIXME:
        offset, length = self._unpack_header(raw, offset)
        offset, (self.command, self.group_type, self.action_num) = \
            _unpack("!BBB", raw, offset)
        offset = _skip(raw, offset, 1)
        offset, (self.group_id, self.counter_id) = _unpack("!LL", raw, offset)

        actions_len = ofp_action_base._MAX_LENGTH * self.action_num
        offset, self.action_list = _unpack_actions(raw, actions_len, offset)
        offset = _skip(raw, offset , (OFP_MAX_ACTION_NUMBER_PER_GROUP - self.action_num) * ofp_action_base._MAX_LENGTH)

        assert length == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_group_mod._MAX_LENGTH
    
    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.command != other.command: return False
        if self.group_type != other.group_type: return False
        if self.action_num != other.action_num: return False
        if self.group_id != other.group_id: return False
        if self.counter_id != other.counter_id: return False
        if self.action_list != other.action_list: return False
        return True
    
    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'command:    ' + str(self.command) + '\n'
        outstr += prefix + 'group_type: ' + str(self.group_type) + '\n'
        outstr += prefix + 'action_num: ' + str(self.action_num) + '\n'
        outstr += prefix + 'group_id:   ' + str(self.group_id) + '\n'
        outstr += prefix + 'counter_id: ' + str(self.counter_id) + '\n'
        outstr += prefix + 'action_list: \n'
        for obj in self.action_list:
            outstr += obj.show(prefix + '  ')
        return outstr
    
@openflow_c_message("OFPT_PORT_MOD", 17)
class ofp_port_mod (ofp_header):
    # _MIN_LENGTH = ofp_header._MIN_LENGTH + 8 + ofp_phy_port._MIN_LENGTH
    _MIN_LENGTH = 136

    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.reason = 0  # 1 byte, ofp_port_reason
        self.desc = None  # ofp_phy_port()
    
        initHelper(self, kw)

    def _validate (self):
        if not isinstance(self.desc, ofp_phy_port):
            return "desc is not class ofp_phy_port"
        return None

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!B", self.reason)
        packed += _PAD * 7
        packed += self.desc.pack()
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)

        offset, self.reason = _unpack("!B", raw, offset)
        offset = _skip(raw, offset, 7)
        self.desc = ofp_phy_port()
        offset = self.desc.unpack(raw, offset)

        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return ofp_port_mod._MIN_LENGTH

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.reason != other.reason: return False
        if self.desc != other.desc: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'reason: ' + str(self.reason)
        outstr += " (" + ofp_port_reason_map[self.reason] + ")\n"
        outstr += prefix + 'desc: \n'
        outstr += self.desc.show(prefix + '  ')
        return outstr
    
@openflow_c_message("OFPT_TABLE_MOD", 18)
class ofp_table_mod (ofp_header):
    _MIN_LENGTH = 8 + ofp_flow_table._MAX_LENGTH  # 152
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        # self.flow_table = None    #ofp_flow_table()
        self.flow_table = ofp_flow_table()
        
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.flow_table.pack()
        return packed
    
    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        if self.flow_table == None:
            self.flow_table = ofp_flow_table()
        offset = self.flow_table.unpack(raw, offset)
        assert length == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_table_mod._MIN_LENGTH
    
    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other) : return False
        if self.flow_table != other.flow_table: return False
        return True
    
    def show (self, prefix=''):
        outstr = ''
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'flow_table: \n'
        outstr += self.flow_table.show(prefix + '  ')
        return outstr   
    
@openflow_c_message("OFPT_MULTIPART_REQUEST", 19,
    request_for="ofp_multipart_reply")
class ofp_multipart_request (ofp_header):
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)
    
@openflow_s_message("OFPT_MULTIPART_REPLY", 20,
    reply_to="ofp_multipart_request")
class ofp_multipart_reply(ofp_header):  # NOT FINISHED YET!
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)

@openflow_c_message("OFPT_BARRIER_REQUEST", 21,
    request_for="ofp_barrier_reply")
class ofp_barrier_request (ofp_header):  # NOT FINISHED YET!
    def __init__ (self, **kw):
        ofp_header.__init__(self)
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        return outstr

@openflow_s_message("OFPT_BARRIER_REPLY", 22,
    reply_to="ofp_barrier_request")
class ofp_barrier_reply (ofp_header):
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        return outstr
    
@openflow_c_message("OFPT_QUEUE_GET_CONFIG_REQUEST", 23,
    request_for="ofp_queue_get_config_reply")
class ofp_queue_get_config_request (ofp_header):  # NOT FINISHED YET!
    def __init__ (self, **kw):
        ofp_header.__init__(self)
       
        initHelper(self, kw)
    
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length


@openflow_s_message("OFPT_QUEUE_GET_CONFIG_REPLY", 24,
    reply_to="ofp_ofp_queue_get_config_request")
class ofp_queue_get_config_reply (ofp_header):  # NOT FINISHED YET!
    def __init__ (self, **kw):
        ofp_header.__init__(self)
    
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length   
        
@openflow_c_message("OFPT_ROLL_REQUEST", 25,
    request_for="ofp_roll_reply")
class ofp_roll_request(ofp_header):  # NOT FINISHED YET!
    def __init__(self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length 
        
@openflow_s_message("OFPT_ROLL_REPLY", 26,
    reply_to="ofp_roll_request")
class ofp_roll_reply(ofp_header):  # NOT FINISHED YET!
    def __init__(self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)  
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length
        
@openflow_c_message("OFPT_GET_ASYNC_REQUEST", 27,
    request_for="ofp_get_async_reply")
class ofp_get_async_request(ofp_header):  # NOT FINISHED YET!
    def __init__(self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)  
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length
        
@openflow_s_message("OFPT_GET_ASYNC_REPLY", 28,
    reply_to="ofp_get_async_request")
class ofp_get_async_reply(ofp_header):  # NOT FINISHED YET!
    def __init__(self, **kw):
        ofp_header.__init__(self)
        
        initHelper(self, kw)  
    
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length
        
@openflow_c_message("OFPT_SET_ASYNC", 29)
class ofp_set_async(ofp_header):  # NOT FINISHED YET!
    def __init__(self, **kw):
        ofp_header.__init__(self)
   
        initHelper(self, kw)
    
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        
        assert length == len(self)
        return offset, length
    
@openflow_c_message("OFPT_METER_MOD", 30)
class ofp_meter_mod(ofp_header):
    _MIN_LENGTH = 24
    def __init__(self, **kw):
        ofp_header.__init__(self)
        self.command = 0  # 1 byte, ofp_meter_mod_command
        self.slot_id = 0
        self.rate = 0  # 2 bytes
        self.meter_id = 0  # 4 bytes

        initHelper(self, kw)
        
    def pack (self):
        assert self._assert()
    
        packed = b""
        packed += ofp_header.pack(self)
        packed += struct.pack("!B", self.command)
        packed += _PAD
        packed += struct.pack("!HLL", self.slot_id, self.meter_id, self.rate)
        packed += _PAD4
        return packed
        
    
    def unpack(self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset, self.command = _unpack("!B", self.command)
        offset = _skip(raw, offset, 1)
        offset, (self.rate, self.meter_id) = _unpack("!HLL", self.slot_id, self.meter_id, self.rate)
        offset = _skip(raw, offset, 4)
        assert length == len(self)
        return offset, length
    
    @staticmethod
    def __len__ ():
        return ofp_meter_mod._MIN_LENGTH

    def __eq__(self, other):
        if type(self) != type(other): return False
        if not ofp_header.__eq__(self, other): return False
        if self.command != other.command: return False
        if self.rate != other.rate: return False
        if self.meter_id != other.meter_id: return False
        if self.slot_id != other.slot_id: return False
        return True
    
    def show(self, prefix=''):
        outstr = ''
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'command:   ' + str(self.command) + '\n' 
        outstr += prefix + 'slot_id:  ' + str(self.slot_id) + '\n' 
        outstr += prefix + 'meter_id:  ' + str(self.meter_id) + '\n' 
        outstr += prefix + 'rate:      ' + str(self.rate) + '\n' 
        return outstr
        
@openflow_c_message("OFPT_COUNTER_MOD", 31)
class ofp_counter_mod(ofp_header):
    _MIN_LENGTH = 8 + ofp_counter._MIN_LENGTH  # 32
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.counter = ofp_counter()
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.counter.pack()
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset = self.counter.unpack(raw, offset)
        
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8 + ofp_counter._MIN_LENGTH  # 32

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'counter: \n'
        outstr += self.counter.show(prefix + '  ')
        return outstr 


@openflow_s_message("OFPT_COUNTER_REQUEST", 32,
    request_for="ofp_counter_reply")
class ofp_counter_request(ofp_header):
    _MIN_LENGTH = 8 + ofp_counter._MIN_LENGTH  # 32
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.counter = ofp_counter()
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.counter.pack()
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset = self.counter.unpack(raw, offset)
        
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8 + ofp_counter._MIN_LENGTH  # 32

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'counter: \n'
        outstr += self.counter.show(prefix + '  ')
        return outstr 

@openflow_s_message("OFPT_COUNTER_REPLY", 33,
    reply_to="ofp_counter_request")
class ofp_counter_reply(ofp_header):
    _MIN_LENGTH = 8 + ofp_counter._MIN_LENGTH  # 32
    
    def __init__ (self, **kw):
        ofp_header.__init__(self)
        self.counter = ofp_counter()
    
        initHelper(self, kw)

    def pack (self):
        assert self._assert()
        
        packed = b""
        packed += ofp_header.pack(self)
        packed += self.counter.pack()
        return packed

    def unpack (self, raw, offset=0):
        offset, length = self._unpack_header(raw, offset)
        offset = self.counter.unpack(raw, offset)
        
        assert length == len(self)
        return offset, length

    @staticmethod
    def __len__ ():
        return 8 + ofp_counter._MIN_LENGTH  # 32

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += ofp_header.show(self, prefix + '  ')
        outstr += prefix + 'counter: \n'
        outstr += self.counter.show(prefix + '  ')
        return outstr

        
        
        
        
def _unpack_actions (b, length, offset=0):
    """
    Parses actions from a buffer
    b is a buffer (bytes)
    offset, if specified, is where in b to start decoding
    returns (next_offset, [Actions])
    """
    if (len(b) - offset) < length: raise UnderrunError
    actions = []
    end = length + offset
    while offset < end:
        (t, l) = struct.unpack_from("!HH", b, offset)
        if (len(b) - offset) < l: raise UnderrunError
        a = _action_type_to_class.get(t)
        if a is None:
            # Use generic action header for unknown type
            # a = ofp_action_generic()
            _log(error="unknown action type")
        else:
            a = a()
        a.unpack(b[offset:offset + l])
        assert len(a) == l
        actions.append(a)
        offset += l
    return (offset, actions)

def _unpack_instructions (b, length, offset=0):
    """
    Parses instructions from a buffer
    b is a buffer (bytes)
    offset, if specified, is where in b to start decoding
    returns (next_offset, [Actions])
    """
    if (len(b) - offset) < length:
        raise UnderrunError
    instructions = []
    end = length + offset
    while offset < end:
        (t, l) = struct.unpack_from("!HH", b, offset)
        if (len(b) - offset) < l:
            raise UnderrunError
        a = _instruction_type_to_class.get(t)
        if a is None:
            # Use generic instruction header for unknown type
            # a = ofp_instruction_generic()
            _log(error="unknown instruction type")
        else:
            a = a()
        a.unpack(b[offset:offset + l])
        assert len(a) == l
        instructions.append(a)
        offset += l
    return (offset, instructions)



def _init ():
    def formatMap (name, m):
        o = name + " = {\n"
        vk = sorted([(v, k) for k, v in m.iteritems()])
        maxlen = 2 + len(reduce(lambda a, b: a if len(a) > len(b) else b,
                                (v for k, v in vk)))
        fstr = "  %-" + str(maxlen) + "s : %s,\n"
        for v, k in vk:
            o += fstr % ("'" + k + "'", v)
        o += "}"
        return o
    
    maps = []
    for k, v in globals().iteritems():
        if (k.startswith("ofp_") and k.endswith("_rev_map") and type(v) == dict):
            maps.append((k[:-8], v))  # cc:delete '_rev_map'
    for name, m in maps:
        # Try to generate forward maps
        forward = dict(((v, k) for k, v in m.iteritems()))  # reverse the map (or dict)
        if len(forward) == len(m):
            if name + "_map" not in globals():  # cc:add '_map'
                globals()[name + "_map"] = forward
        else:
            print(name + "_rev_map is not a map")
    
        # Try to generate lists
        v = m.values()
        v.sort()
        if v[-1] != len(v) - 1:
            # Allow ones where the last value is a special value (e.g., VENDOR)
            del v[-1]
        if len(v) > 0 and v[0] == 0 and v[-1] == len(v) - 1:
            globals()[name] = v  # list:values of *_rev_map
    
        # Generate gobals
        for k, v in m.iteritems():
            globals()[k] = v

_init()

# Values from macro definitions
OFP_FLOW_PERMANENT = 0
OFP_DL_TYPE_ETH2_CUTOFF = 0x0600
DESC_STR_LEN = 256
OFPFW_ICMP_CODE = OFPFW_TP_DST
OFPQ_MIN_RATE_UNCFG = 0xffff
OFP_VERSION = 0x04  # OpenFlow version -> POF
OFP_MAX_TABLE_NAME_LEN = 32
OFP_DL_TYPE_NOT_ETH_TYPE = 0x05ff
OFP_DEFAULT_MISS_SEND_LEN = 128
OFP_MAX_PORT_NAME_LEN = 64  # changed from 16 to 64
POF_NAME_MAX_LENGTH = 64  # add new
OFP_SSL_PORT = 6633
OFPFW_ICMP_TYPE = OFPFW_TP_SRC
OFP_TCP_PORT = 6633
SERIAL_NUM_LEN = 32
OFP_DEFAULT_PRIORITY = 0x8000
OFP_VLAN_NONE = 0xffff
OFPQ_ALL = 0xffffffff
