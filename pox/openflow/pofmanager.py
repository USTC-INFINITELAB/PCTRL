# Copyright 2014, 2015 USTC INFINITE Laboratory
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


from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of
from pox.openflow.pmdatabase import PMdatabase

import time

log = core.getLogger()

OFPROTOCOLID_INVALID = 0
FLOWTABLEID_INVALID = -1
FLOWENTRYID_INVALID = -1
DEFAULT_SAVE_FILE_NAME = 'Database.db'

class Switch (EventMixin):
    def __init__ (self):
        self.device_id = None
        #self.features_reply = None   #ofp_features_reply
        self.connection = None
        #self.ports = None
        #self._listeners = None
        self._connected_at = None
      
    def set_device_id(self, device_id):
        self.device_id = device_id
        
    def get_device_id(self):
        return self.device_id
   
    def disconnect (self):
        if self.connection is not None:
            log.debug("Disconnect %s" % (self.connection,))
            #self.connection.removeListeners(self._listeners)
            self.connection = None
            #self._listeners = None

    def connect (self, connection):
        #print "connection.dpid",connection.dpid
        #print 'connection.features',connection.features
        if self.device_id is None:
            self.device_id = connection.dpid
        assert self.device_id == connection.dpid
        self.disconnect()
        log.debug("Connect %s" % (connection,))
        self.connection = connection
        #self._listeners = self.listenTo(connection)
        self._connected_at = time.time()
        
        

class PofManager(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self, priority = of.OFP_DEFAULT_PRIORITY)
        self.database = PMdatabase()
        self.switches = {}  #device_id:Switch()
          
    # Protocol functions
    def add_protocol(self, protocol_name, field_list):   # protocol_name: string, field_list: list of ofp_match20
        if field_list == None or len(field_list) == 0 or False == self.check_field_list(field_list):
            log.error("Add protocol failed")
            return OFPROTOCOLID_INVALID
        protocol_id = self.database.add_protocol(protocol_name, field_list) 
        log.info("Add Protocol: [protocol_name] " + protocol_name + " [protocol_id] " + str(protocol_id))
        return protocol_id
    
    def get_protocol_by_id(self, protocol_id):
        protocol_map = self.database.get_protocol_map()
        if protocol_map is None:
            return None
        return protocol_map.get(protocol_id)
    
    def get_protocol_by_name(self, protocol_name):
        protocol_name_map = self.database.get_protocol_name_map()
        if protocol_name_map is None:
            return None
        protocol_id = protocol_name_map.get(protocol_name)
        if protocol_id is not None:
            return self.get_protocol_by_id(protocol_id)
        return None
    
    def check_field_list(self, field_list):
        if field_list is None:
            return False
        previous_field_offset = 0
        previous_field_length = 0
        for field in field_list:
            if field.offset < previous_field_offset + previous_field_length:
                return False
            previous_field_offset = field.offset
            previous_field_length = field.length
        return True
    
    def get_all_protocol(self):
        protocol_list = []
        protocol_map = self.database.get_protocol_map()
        if protocol_map is not None:
            for protocol_id in protocol_map:
                protocol_list.append(protocol_map.get(protocol_id))
        return protocol_list
        
    def modify_protocol(self, protocol_id, new_field_list):
        protocol = self.get_protocol_by_id(protocol_id)
        if protocol is None:
            log.error("no such protocol")
            return False
        if new_field_list == None or len(new_field_list) == 0 or False == self.check_field_list(new_field_list):
            log.error("Modify protocol failed, wrong field_list")
            return False
        return self.database.modify_protocol(protocol, new_field_list)
        
    def del_protocol(self, protocol_id):
        protocol = self.get_protocol_by_id(protocol_id)
        if protocol is None:
            log.error("no such protocol")
            return False
        log.info("Delete Protocol: " + protocol.protocol_name + 'protocol_id=' + str(protocol_id))
        field_list = protocol.get_all_field()
        if field_list is not None:
            for field in field_list:
                self.delete_field(field.field_id)
        self.database.del_protocol(protocol)
        return True
        
    def del_all_protocol(self):
        protocol_list = self.get_all_protocol()
        if protocol_list is not None:
            for protocol in protocol_list:
                self.del_protocol(protocol.get_protocol_id())
    
    # Field functions
    def new_field(self, field_name, field_offset, field_length):   #return field_id
        field_id = self.database.new_field(field_name, field_offset, field_length)
        return field_id
    
    def modify_field(self, field_id, field_name, field_offset, field_length):  #return boolean
        return self.database.modify_field(field_id, field_name, field_offset, field_length)
        
    def delete_field(self, field_id):
        return self.database.del_field(field_id)
    
    def get_field(self, field):   #type(field) is integer or string (field_id or field_name)
        if isinstance(field, int):
            return self.database.get_field_by_id(field)   #return a ofp_match20
        elif isinstance(field, str):
            return self.database.get_field_by_name(field)   #return a list of ofp_match20
        return None
    
    def get_all_field(self):   # return a list of ofp_match20
        return self.database.get_all_field()
        
    def get_belonged_protocol(self, field_id):
        protocol_map = self.database.get_protocol_map()
        if protocol_map != None:
            for protocol_id in protocol_map:
                field_list = protocol_map.get(protocol_id).get_all_field()
                for field in field_list:
                    if field.field_id == field_id:
                        return protocol_map.get(protocol_id)
        return None
    
    # METADATA functions
    def modify_metadata(self, metadata_list):  # metadata_list: a list of ofp_match20
        self.database.modify_metadata(metadata_list)
    
    def get_metadata(self):
        return self.database.get_metadata()     #return a list of ofp_match20
    
    def get_metadata_field(self, field_name):   # return a ofp_match20
        return self.database.get_metadata_field(field_name)
    
    def remove_all_metadata(self):
        self.database.get_metadata().clear()
        
    def new_metadata_field(self, field_name, field_offset, field_length):
        self.database.new_metadata_field(field_name, field_offset, field_length)
    
    # Flow Table functions
    def add_flow_table(self, switch_id, table_name, table_type, table_size, match_field_list = []): 
        # Have been tested
        if (switch_id not in self.switches) or (table_name == None) or (len(table_name) == 0):
            log.error("no such switch_id or wrong table name")
            return FLOWTABLEID_INVALID
        if (table_size == 0) or (table_type < 0) or (table_type >= of.OF_MAX_TABLE_TYPE):
            log.error("wrong table size or wrong table type")
            return FLOWTABLEID_INVALID
        if (table_type == of.OF_LINEAR_TABLE) and (len(match_field_list) != 0):
            log.error("wrong match_field_list")
            return FLOWTABLEID_INVALID
        if (table_type != of.OF_LINEAR_TABLE) and (len(match_field_list) == 0):
            log.error("wrong match_field_list")
            return FLOWTABLEID_INVALID
        
        field_num = len(match_field_list)  # calculate the field_num
        key_length = 0
        for field in match_field_list:     # calculate the key_length
            key_length += field.length
            
        global_table_id = self.database.add_flow_table(switch_id, table_name, table_type, key_length, table_size, field_num, match_field_list)
        if global_table_id == FLOWTABLEID_INVALID:
            log.error("ERROR when add flow table in PMDatabase")
            return FLOWTABLEID_INVALID
        flow_table = self.database.get_flow_table(switch_id, global_table_id)
        msg = of.ofp_table_mod()
        msg.flow_table = flow_table
        self.write_of(switch_id, msg)
        msg_info = ''
        msg_info += ('ADD <table[' + str(flow_table.table_type) + '][' + str(flow_table.table_id) + ']> ')
        msg_info += ('[G_TID] ' + str(global_table_id) + ' [T_NAME] ' + flow_table.table_name)
        #log.info('ADD <table[' + str(flow_table.table_type) + '][' + str(flow_table.table_id) + ']> ' + flow_table.table_name)
        log.info(msg_info)
        #self.add_sended_msg(switch_id, msg)
        return global_table_id
        
    def get_all_flow_table(self, switch_id):   # return a list of ofp_flow_table
        # Have been tested
        flow_table_map = self.database.get_flow_table_map(switch_id)
        if flow_table_map is None:
            return None
        return flow_table_map.values()
    
    def get_flow_table(self, switch_id, global_table_id):   # return ofp_flow_table
        # Have been tested
        return self.database.get_flow_table(switch_id, global_table_id)
    
    def get_flow_table_id(self, switch_id, table_name):   # return global_table_id
        return self.database.get_flow_table_id(switch_id, table_name)
    
    def del_empty_flow_table(self, switch_id, global_table_id):
        # Have been tested
        flow_entry_map = self.database.get_flow_entries_map(switch_id, global_table_id)
        if len(flow_entry_map) != 0:
            log.error("table is not empty")
            return False
        flow_table = self.get_flow_table(switch_id, global_table_id)
        if flow_table is None:
            log.error("table doesn't exist, no need to delete")
            return True
        self.database.delete_flow_table(switch_id, flow_table.table_type, global_table_id)
        flow_table.command = of.OFPTC_DELETE  
        table_mod = of.ofp_table_mod()
        table_mod.flow_table = flow_table
        self.write_of(switch_id, table_mod)      # send to switch
        return True
        # TODO: add sended msg
    
    def del_flow_table_and_all_sub_entries(self, switch_id, global_table_id):
        # Have been tested
        flow_entry_map = self.database.get_flow_entries_map(switch_id, global_table_id)
        if flow_entry_map is None:
            log.error("This table doesn't exist, no need to delete!")
            return True
        for entry_id in flow_entry_map.keys():
            self.delete_flow_entry(switch_id, global_table_id, entry_id)
        self.del_empty_flow_table(switch_id, global_table_id)   #now, the table is empty
        return True
    
    def del_all_flow_tables(self, switch_id):
        # Have been tested
        table_list = self.get_all_flow_table(switch_id)    # list of ofp_flow_table
        if table_list is not None:
            for flow_table in table_list:
                global_table_id = self.parse_to_global_table_id(switch_id, flow_table.table_type, flow_table.table_id)
                self.del_flow_table_and_all_sub_entries(switch_id, global_table_id)
        return True
    
    def get_flow_table_no_base(self, switch_id, table_type):
        return self.database.get_flow_table_no_base(switch_id, table_type)
    
    def parse_to_small_table_id(self, switch_id, global_table_id):
        return self.database.parse_to_small_table_id(switch_id, global_table_id)
    
    def parse_to_global_table_id(self, switch_id, table_type, small_table_id):
        return self.database.parse_to_global_table_id(switch_id, table_type, small_table_id)
    
    # Flow Entry functions
    def add_flow_entry(self, switch_id, global_table_id, matchx_list, instruction_list, priority = 0, counter_enable = True):
        # return entry_id
        # Have been tested
        if not isinstance(matchx_list, list):
            log.error("wrong matchx_list")
            return FLOWENTRYID_INVALID
        if not isinstance(instruction_list, list):
            log.error("wrong instruction_list")
            return FLOWENTRYID_INVALID
        
        flow_table = self.get_flow_table(switch_id, global_table_id)
        if flow_table is None or not isinstance(flow_table, of.ofp_flow_table):
            log.error("wrong flow table")
            return FLOWENTRYID_INVALID
        
        table_type = flow_table.table_type
        if table_type == of.OF_LINEAR_TABLE and len(matchx_list) != 0:
            return FLOWENTRYID_INVALID
        if table_type != of.OF_LINEAR_TABLE and len(matchx_list) == 0:
            return FLOWENTRYID_INVALID
        
        if len(matchx_list) != 0:
            total_field_length = 0
            for matchx in matchx_list:
                if not isinstance(matchx, of.ofp_matchx):
                    log.error("wrong matchx")
                    return FLOWENTRYID_INVALID
                total_field_length += matchx.length
            if total_field_length != flow_table.key_length:
                log.error("wrong total field_length")
                return FLOWENTRYID_INVALID
                
        #TODO: CHECK DUPLICATION
        
        match_field_num = len(matchx_list)
        instruction_num = len(instruction_list)
        flow_entry_id = self.database.add_flow_entry(switch_id, global_table_id, match_field_num, matchx_list, instruction_num, instruction_list, priority, counter_enable)
        flow_entry = self.get_flow_entry(switch_id, global_table_id, flow_entry_id)
        self.write_of(switch_id, flow_entry)
        log.info('ADD <entry[' + str(flow_entry.table_type) + '][' + str(flow_entry.table_id) + '][' + str(flow_entry.index) + ']>')
        return flow_entry_id
    
    def get_flow_entry(self, switch_id, global_table_id, flow_entry_id):   #return ofp_flow_mod
        # Have been tested
        return self.database.get_flow_entry(switch_id, global_table_id, flow_entry_id)
    
    def get_all_flow_entry(self, switch_id, global_table_id):   #return a list of ofp_flow_mod
        # Have been tested
        #flow_entry_list = []
        flow_entry_map = self.database.get_flow_entries_map(switch_id, global_table_id)
        if flow_entry_map is None:
            return None
        return flow_entry_map.values()
    
    def get_all_matched_flow_entry(self, switch_id, global_table_id, matchx_list):   #return a list of ofp_flow_mod 
        pass
    
    def get_exact_matched_flow_entry(self, switch_id, global_table_id, matchx_list):  #return ofp_flow_mod
        pass
    
    def modify_flow_entry(self, switch_id, global_table_id, flow_entry_id, matchx_list, instruction_list, priority = 0, counter_enable = True):   # return boolean
        # Have been tested
        if not isinstance(matchx_list, list):
            log.error("wrong matchx_list")
            return False
        if not isinstance(instruction_list, list):
            log.error("wrong instruction_list")
            return False
        
        flow_table = self.get_flow_table(switch_id, global_table_id)
        if flow_table is None or not isinstance(flow_table, of.ofp_flow_table):
            log.error("wrong flow table")
            return False
        table_type = flow_table.table_type
        if table_type == of.OF_LINEAR_TABLE and len(matchx_list) != 0:
            return False
        if table_type != of.OF_LINEAR_TABLE and len(matchx_list) == 0:
            return False
        
        if len(matchx_list) != 0:
            total_field_length = 0
            for matchx in matchx_list:
                if not isinstance(matchx, of.ofp_matchx):
                    log.error("wrong matchx")
                    return False
                total_field_length += matchx.length
            if total_field_length != flow_table.key_length:
                log.error("wrong total field_length")
                return False
        """
        old_flow_mod = self.database.get_flow_entry(switch_id, global_table_id, flow_entry_id)
        if old_flow_mod is None:
            return False
        """
        #TODO: CHECK DUPLICATION
        
        match_field_num = len(matchx_list)
        instruction_num = len(instruction_list)  #FIXME:
        self.database.modify_flow_entry(switch_id, global_table_id, flow_entry_id, match_field_num, matchx_list, instruction_num, instruction_list, priority, counter_enable)
        flow_entry = self.get_flow_entry(switch_id, global_table_id, flow_entry_id)
        flow_entry.command = of.OFPFC_MODIFY  # 1
        self.write_of(switch_id, flow_entry)
        log.info('MOD <entry[' + str(flow_entry.table_type) + '][' + str(flow_entry.table_id) + '][' + str(flow_entry.index) + ']>')
        # TODO: add sended msg
        return True
    
    def delete_flow_entry(self, switch_id, global_table_id, index):
        #Have been tested
        flow_entry = self.database.get_flow_entry(switch_id, global_table_id, index)
        if flow_entry is None or not isinstance(flow_entry, of.ofp_flow_mod):
            return None
        self.database.delete_flow_entry(switch_id, global_table_id, index)   # delete flow_entry from the database
        flow_entry.command = of.OFPFC_DELETE  # 3
        self.write_of(switch_id, flow_entry)
        log.info('DELETE <entry[' + str(flow_entry.table_type) + '][' + str(flow_entry.table_id) + '][' + str(flow_entry.index) + ']>')
        # TODO: add sended msg
        # TODO: delete match key
    
    def check_flow_entry_reduplication(self):
        pass
    
    # Port functions
    def set_port_status(self, switch_id, port_status):
        self.database.set_port_status(switch_id, port_status)
        #TODO: need to display in the GUI
    
    def get_port_status(self, switch_id, port_id):
        #return self.database.get_switch_DB(switch_id).get_port(port_id)
        return self.database.get_port_status(switch_id, port_id)
    
    def get_port_id_by_name(self, switch_id, port_name):
        return self.database.get_switch_DB(switch_id).get_port_id_by_name(port_name)
    
    def set_port_of_enable(self, device_id, port_id, onoff = True):
        self.database.set_port_of_enable(device_id, port_id, onoff)
        port = self.database.get_port_status(device_id, port_id)   # instance of ofp_port_status
        if port != None:
            msg = of.ofp_port_mod(reason = of.OFPPR_MODIFY)    # OFPPR_MODIFY = 2
            msg.desc = port.desc
            self.write_of(device_id, msg)
            #log.info("Port [" + str(port.desc.port_id) + "] Set pof enable [" + str(port.desc.device_id) + "]")
            log.info("Port [" + "0x%x" % port.desc.port_id + "] Set POF Enable [" + str(port.desc.device_id) + "]")
            
    def get_all_port_id(self, switch_id):
        return self.database.get_all_port_id(switch_id)   # return a list of port_id
            
    # Switch functions
    def add_switch(self, switch_id, sw):
        self.switches[switch_id] = sw
    
    def remove_switch(self, switch_id):
        self.switches.pop(switch_id)
        
    def get_switch_by_id(self, switch_id):
        return self.switches.get(switch_id)
    
    def check_switch_connected(self, switch_id):
        pass   #FIXME:
    
    def get_all_switch_id(self):
        return self.database.get_all_switch_id()
    
    def send_all_of_messages_base_on_DB(self):
        pass  #FIXME:
    
    def write_of(self, switch_id, ofp):
        #time.sleep(0.1)
        sw = self.get_switch_by_id(switch_id)
        sw.connection.send(ofp)
        
    # Resource report functions
    def get_resource_report_map(self, switch_id):
        return self.database.get_resource_report_map(switch_id)
    
    def get_resource_report(self, switch_id, slot_id):
        return self.database.get_resource_report(switch_id, slot_id)
    
    # Counter functions
    def allocate_counter(self, switch_id):   # return counter_id
        pass
    
    def free_counter(self, switch_id, counter_id): # return ofp_counter
        pass
    
    def free_all_counters(self, switch_id):
        pass
    
    def reset_counter(self, switch_id, counter_id, writo_to_switch=True):   #return boolean
        pass
    
    def query_counter_value(self, switch_id, counter_id):   # return a ofp_counter
        if self.database.get_counter(switch_id, counter_id) is None:
            return None
        """
        value = of.ofp_counter()
        value.counter_id = counter_id
        counter_reply_list = []
        """
        counter_req = of.ofp_counter_request()
        counter_req.counter.counter_id = counter_id
        counter_req.counter.command = of.OFPCC_QUERY
        self.write_of(switch_id, counter_req)
        #FIXME:
    
    # Meter functions
    def add_meter_entry(self, switch_id, rate):  # return meter_id
        meter_id = self.database.add_meter_entry(switch_id, rate)
        meter_mod = self.get_meter(switch_id, meter_id)
        if meter_mod is not None:
            meter_mod.command = of.OFPMC_ADD
            self.write_of(switch_id, meter_mod)
        return meter_id
    
    def free_meter(self, switch_id, meter_id):  # return ofp_meter_mod
        pass
    
    def free_all_meters(self, switch_id):
        pass
    
    def get_meter(self, switch_id, meter_id):  # return ofp_meter_mod
        return self.database.get_meter(switch_id, meter_id)
        
    def get_all_meters(self, switch_id):   #return a list of ofp_meter_mod
        pass
    
    def modify_meter(self, switch_id, meter_id, rate):   #return boolean
        pass
    
    # Group functions
    def add_group_entry(self, switch_id, group_type, action_num, action_list, counter_enable = True):
        pass
    
    def free_group_entry(self, switch_id, group_id):  #return ofp_group_mod
        pass
    
    def get_group_entry(self, switch_id, group_id):  #return ofp_group_mod
        pass
    
    def modify_group_entry(self, switch_id, group_id, group_type, action_num, action_list, counter_enable = True):
        pass
    
    def get_all_groups(self, switch_id):
        pass
    
    def free_all_groups(self, switch_id):
        pass
    
    # Matchx functions
    def new_matchx(self, field, value, mask):
        """
        field: field_id or an instance of ofp_match20
        value: hexadecimal string
        mask: hexadecimal string
        """
        if isinstance(field, int):   #field_id
            field = self.get_field(field)   # get match20
        elif isinstance(field, of.ofp_match20):
            pass
        else:
            log.error("Wrong parameter: field")
        matchx = of.ofp_matchx(match20 = field)
        matchx.value = value
        matchx.mask = mask
        return matchx
    
    # Instruction functions
    def new_ins_goto_table(self, switch_id, next_global_table_id, packet_offset = 0):    # 1
        next_flow_table = self.database.get_flow_table(switch_id, next_global_table_id)
        match_field_num = next_flow_table.match_field_num
        match_field_list = next_flow_table.match_field_list
        instruction = of.ofp_instruction_goto_table()
        instruction.next_table_id = next_global_table_id
        instruction.match_field_num = match_field_num
        instruction.match_list = match_field_list
        instruction.packet_offset = packet_offset
        return instruction
    
    def new_ins_goto_direct_table(self, next_global_table_id, index_type, packet_offset, index_value, index_field = None):   # 8
        instruction = of.ofp_instruction_goto_direct_table()
        instruction.next_table_id = next_global_table_id
        instruction.index_type = index_type
        instruction.packet_offset = packet_offset
        instruction.index_value = index_value
        instruction.index_field = index_field
        return instruction
        
    def new_ins_write_metadata(self, metadata_offset, write_length, value):  # 2
        instruction = of.ofp_instruction_write_metadata()
        instruction.metadata_offset = metadata_offset
        instruction.write_length = write_length
        instruction.value = value
        return instruction
    
    def new_ins_write_metadata_from_packet(self, metadata_offset, write_length, packet_offset = 0):  # 7
        instruction = of.ofp_instruction_write_metadata_from_packet()
        instruction.metadata_offset = metadata_offset
        instruction.write_length = write_length
        instruction.packet_offset = packet_offset
        return instruction
    
    def new_ins_meter(self, meter_id):
        instruction = of.ofp_instruction_meter()
        instruction.meter_id = meter_id
        return instruction
        
    def new_ins_calculate_field(self, calc_type, src_value_type, des_field, src_value, src_field = None):
        instruction = of.ofp_instruction_calculate_field()
        instruction.calc_type = calc_type  # ofp_calc_type_map, +,-,....
        instruction.src_value_type = src_value_type   #0: use srcField_Value; 1: use srcField;
        instruction.des_field = des_field
        instruction.src_value = src_value
        instruction.src_field = src_field
        return instruction
    
    def new_ins_apply_actions(self, action_list = []):   # 4
        action_num = len(action_list)
        instruction = of.ofp_instruction_apply_actions()
        instruction.action_num = action_num
        instruction.action_list = action_list
        return instruction
    
    # Action functions
    def new_action_output(self, port_id_value_type, metadata_offset, metadata_length, packet_offset, port_id, port_id_field = None):  # 0
        #port_id_value_type: 0 for immediate number and 1 for field, metadata_offset:int
        action = of.ofp_action_output()
        action.port_id_value_type = port_id_value_type
        action.metadata_offset = metadata_offset
        action.metadata_length = metadata_length
        action.packet_offset = packet_offset
        action.port_id = port_id
        action.port_id_field = port_id_field
        return action
    
    def new_action_set_field(self, field_setting):  # 1
        #field_setting:ofp_matchx
        action = of.ofp_action_set_field()
        action.field_setting = field_setting
        return action
    
    def new_action_set_field_from_metadata(self, field_setting, metadata_offset):  # 2
        #field_setting:ofp_matchx, metadata_offset:int
        action = of.ofp_action_set_field_from_metadata()
        action.field_setting = field_setting
        action.metadata_offset = metadata_offset
        return action
    
    def new_action_modify_field(self, match_field, increment):  #3
        #match_field:ofp_match20, increment:int
        action = of.ofp_action_modify_field()
        action.match_field = match_field
        action.increment = increment
        return action
        
    def new_action_add_field(self, field_id, field_position, field_length, field_value):  #4
        #field_id:int, field_position:int, field_length:int, field_value:string
        action = of.ofp_action_add_field()
        action.field_id = field_id
        action.field_position = field_position
        action.field_length = field_length
        action.field_value = field_value
        return action
    
    def new_action_delete_field(self, field_position, length_value_type, length_value, length_field = None):  #5
        """generate a instance of ofp_action_delete_field (action_type: 5)
        
        Args:
        
        Returns:
            A instance of ofp_action_delete_field (action_type: 5)
        
        Raises:
        """
        #field_position:int, length_value_type:0 for immediate number and 1 for field, length_value:int, length_field:ofp_match20
        action = of.ofp_action_delete_field()
        action.tag_position = field_position
        action.tag_length_value_type = length_value_type
        action.tag_length_value = length_value
        action.tag_length_field = length_field
        return action
    
    def new_action_calculate_checksum(self,checksum_pos_type,calc_pos_type,checksum_position,checksum_length,calc_start_position,calc_length): #6
        #
        action = of.ofp_action_calculate_checksum()
        action.checksum_pos_type = checksum_pos_type     #0: packet; 1: metadata
        action.calc_pos_type = calc_pos_type             #0: packet; 1: metadata
        action.checksum_position = checksum_position
        action.checksum_length = checksum_length
        action.calc_start_position = calc_start_position
        action.calc_length = calc_length
        return action
    
    def new_action_group(self, group_id):  #7
        action = of.ofp_action_group()
        action.group_id = group_id
        return action
    
    def new_action_drop(self, reason):  #8
        action = of.ofp_action_drop()
        action.reason = reason
        return action
    
    def new_action_packetin(self, reason):  #9
        """packet_in_reason
        'OFPR_NO_MATCH'    : 0,
        'OFPR_ACTION'      : 1,
        'OFPR_INVALID_TTL' : 2,
        """
        action = of.ofp_action_packetin()
        action.reason = reason
        return action
    
    def new_action_counter(self, counter_id):  #10
        action = of.ofp_action_counter()
        action.counter_id = counter_id
        return action
    
    def save_all_data_into_file(self, file_name = DEFAULT_SAVE_FILE_NAME):
        pass
    
    def save_metadata_into_file(self):
        pass
    
    def load_all_data_from_file(self):
        pass
    
    def load_metadata_from_file(self):
        pass
    
    def send_all_of_msg_based_on_DB(self):
        pass
    
    # Handlers of POF messages
    def _handle_FeaturesReceived(self, event):
        #print "PofManager: Features Reply Received"
        features_reply = event.ofp
        if not isinstance(features_reply, of.ofp_features_reply):
            log.error("wrong features_reply")
        
        device_id = event.dpid
        sw = Switch()
        #sw.set_device_id(features_reply.device_id)
        sw.set_device_id(device_id)
        sw.connect(event.connection)
        self.add_switch(device_id, sw)
        
        self.database.add_switch_DB(device_id)
        self.database.set_features(device_id, features_reply)
        
    def _handle_ResourceReport(self, event):
        #print "PofManager: Resource Report Received"
        switch_id = event.dpid
        resource_report = event.ofp
        self.database.set_resource_report(switch_id, resource_report)
        
    def _handle_PortStatus(self, event):
        #print "PofManager: Port Status Received"     #for test
        port_status = event.ofp    # ofp_port_status 
        port = port_status.desc    # ofp_phy_port
        if port_status.reason == of.OFPPR_ADD:    # 0
            self.database.set_port_status(port.device_id, port_status)
            #log.info("Port [" + str(port.port_id) + "] added for Switch [" + str(port.device_id) + "]")
            log.info("Port [" + "0x%x" % port.port_id + "] added for Switch [" + str(port.device_id) + "] [Port name] " + port.name)
            #self.set_port_of_enable(event.dpid, port.port_id)    #set pof_enable
        elif port_status.reason == of.OFPPR_DELETE: # 1
            self.database.del_port_status(port.device_id, port.port_id)
            #log.info("Port [" + str(port.port_id) + "] deleted for Switch [" + str(port.device_id) + "]")
            log.info("Port [" + "0x%x" % port.port_id + "] deleted for Switch [" + str(port.device_id) + "]")
        elif port_status.reason == of.OFPPR_MODIFY:   # 2
            self.database.set_port_status(port.device_id, port_status)
            #log.info("Port [" + str(port.port_id) + "] modified for Switch [" + str(port.device_id) + "]")
            log.info("Port [" + "0x%x" % port.port_id + "] modified for Switch [" + str(port.device_id) + "]")
            
    def _handle_CounterReply(self, event):
        print 'PofManager: CounterReply received'
        
        
        
def launch():
    core.registerNew(PofManager)