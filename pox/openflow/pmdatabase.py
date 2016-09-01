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


from pox.lib.revent.revent import EventMixin
from pox.core import core
import pox.openflow.libpof_02 as of

#from collections import defaultdict

import sys
import copy
from cookielib import offset_from_tz_string

log = core.getLogger()

FIRST_ENTRY_TABLE_ID = 0
FIRST_ENTRY_TABLE_NAME = 'FirstEntryTable'
DEFAULT_SAVE_FILE_NAME = 'Database.db'
SWITCHID_INVALID = 0
OFPROTOCOLID_INVALID = 0
FIELDID_INVALID = 0
OFPROTOCOLID_START = 1
FIELDID_START = 1
FLOWENTRYID_INVALID = -1
FLOWTABLEID_INVALID = -1
FLOWENTRYID_START = 0
FLOWTABLEID_START = 0
COUNTERID_INVALID = 0
GROUPID_INVALID = 0
METER_INVALID = 0
COUNTERID_START = 1
GROUPID_START = 1
METER_START = 1

class Protocol(object):
    
    def __init__(self,  **kw):
        self.protocol_name = ''
        self.protocol_id = 0     # 2 bytes
        self.total_length = 0    # 2 bytes
        self.field_list = []     # ofp_match20      
        
    def get_field(self, field):
        if isinstance(field, int):
            for f in self.field_list:
                if f.field_id == field:
                    return f
        elif isinstance(field, str):
            for f in self.field_list:
                if f.field_name == field:
                    return f
        return None
    
    def get_all_field(self):
        return self.field_list
    
    def set_field(self, field_list):
        self.field_list = field_list
        
    def get_field_num(self):
        return len(self.field_list)
    
    def get_protocol_id(self):
        return self.protocol_id
    """
    def add_new_field(self, field_name, offset, length):
        field_id = self.field_id_assigned
        new_field = Field()
        new_field.add(field_name, field_id, offset, length)
        
        self.field_name_dict[field_name] = field_id
        self.field_dict[field_id] = new_field
        self.totallength += length
        
        self.field_id_assigned += 1
        return new_field
    
    def mod_field(self, field_id, field_name, offset, length): # or delete all then add new
        self.field_dict[field_id].modify(field_name, offset, length)
        return
    
    def del_field(self, field_id):
        deleted_field = self.field_dict.pop(field_id)
        return deleted_field
    
    def show(self,prefix = ''):
        outstr = ''
        outstr += prefix + 'protocol_name:' + str(self.protocol_name) + '\n'
        outstr += prefix + 'protocol_id:  ' + str(self.protocol_id) + '\n'
        outstr += prefix + 'totallength:  ' + str(self.totallength) + '\n'
        for each_field_id in self.field_dict.keys():
            outstr += self.field_dict[each_field_id].show(prefix + '  ') 
        return outstr
    
    def to_ofp_match20_list(self):
        ofp_match20_list = []
        for each_field_id in self.field_dict.keys():
            ofp_match20_list.append(self.field_dict[each_field_id].to_ofp_match20())
            
        return ofp_match20_list
    
    def to_match(self, *field_name):
        match_list = []
        for each_field_name in field_name:
            field_id = self.field_name_dict[each_field_name]
            field = self.field_dict[field_id]
            ofp_match20 = field.to_ofp_match20()
            match_list.append(ofp_match20)
        return match_list
    """

        
class ProtocolDB(object):
    
    def __init__(self):
        self.protocol_name_dict = {}  # {protocol_name: protocol_id}
        self.protocol_dict = {}    # {protocol_id: protocol}
        
        self.protocol_id_assigned = 1
        
    def add_new_protocol(self, protocol):        
        if isinstance(protocol, Protocol):
            protocol_id = self.protocol_id_assigned
            protocol_name = protocol.protocol_name
            protocol.protocol_id = protocol_id
            
            self.protocol_name_dict[protocol_name] = protocol_id    
            self.protocol_dict[protocol_id] = protocol
            
            self.protocol_id_assigned += 1
        
    def get_protocol_by_id(self, protocol_id):
        return self.protocol_dict.get(protocol_id)
    
    def get_protocol_by_name(self, protocol_name):
        protocol_id = self.protocol_name_dict.get(protocol_name)
        return self.get_protocol_by_id(protocol_id)

    def show(self): 
        outstr = ''       
        for each_protocol_id in self.protocol_dict.keys():
            outstr += self.protocol_dict.get(each_protocol_id).show()           
        return outstr

class PMFlowTableDB(object):
    
    def __init__(self, **kw):
        self.flow_table_id = 0       # global_table_id
        self.flow_entries_map = {}   # entry_id : flow_entry
        self.flow_entry_no = 0
        self.free_flow_entry_id_list = []
        self.match_key_map = {}    #key_string: entry_id
        """
        self.flow_table_dict = {}    # {flow_table_id: flow_table}
        self.flow_table_name = {}    # {flow_table_name: flow_table_id}
        self.flow_table_entry = defaultdict(lambda: defaultdict())   # {flow_table_id: flow_entry_id}
               
        #self.flow_table_id_assigned = 0
        """
    def get_new_flow_entry_id(self):
        if 0 == len(self.free_flow_entry_id_list):
            new_flow_entry_id = self.flow_entry_no
            self.flow_entry_no += 1
        else:
            new_flow_entry_id = self.free_flow_entry_id_list.pop(0)
        return new_flow_entry_id
    
    def delete_flow_entry(self, index):
        flow_entry = self.flow_entries_map.pop(index)
        self.free_flow_entry_id_list.append(index)
        self.free_flow_entry_id_list.sort()
        return flow_entry
    
    def get_flow_entry(self, entry_id):
        return self.flow_entries_map.get(entry_id)
    
    def get_flow_entries_map(self):
        return self.flow_entries_map
    
    """
    def add_flow_table(self, flow_table):
        if isinstance(flow_table, of.ofp_flow_table): 
            if flow_table.tableId not in self.flow_table_dict.keys():
                self.flow_table_dict[flow_table.tableId] = flow_table
                self.flow_table_name[flow_table.tableName] = flow_table.tableId
                return True
            else:
                log.error('This table ID is already exist.')
        else:
            log.info('Add flow_table type error in FlowTableDB()')
    
    def get_flow_table(self, flow_table_id):
        return self.flow_table_dict[flow_table_id]
    
    def get_flow_table_by_name(self, table_name):
        flow_table_id = self.flow_table_name[table_name]
        return self.flow_table_dict[flow_table_id]
    
    def del_flow_table(self, flow_table_id):     
        self.flow_table_dict.pop(flow_table_id)        
        
    def add_flow_entry(self, table_id, flow_mod):
        flow_entry_id = flow_mod.index
        if flow_entry_id != None:
            self.flow_table_entry[table_id][flow_entry_id] = flow_mod
        else:
            log.error('Flow entry id is None.')
        
    def get_flow_entry(self, table_id, flow_entry_id):
        if table_id in self.flow_table_entry.keys():
            if flow_entry_id in self.flow_table_entry[table_id].keys():                
                return self.flow_table_entry[table_id][flow_entry_id]
            else:
                log.error('Flow entry id does not exist.')
        else:
            log.error('Table id does not exist.')
            
    def del_flow_entry(self, table_id, flow_entry_id):
        return self.flow_table_entry[table_id].pop(flow_entry_id)
    """
    
class Metadata(object): # wenjian
    
    def __init__(self):
        self.metadata_name_dict = {} # {field_name: filed_id}
        self.metadata_dict = {} # {field_id: field}
        self.metadata_id_assigned = 0    
        
    def add_metadata(self, metadata_name, offset, length):
        metadata_id = self.metadata_id_assigned
        new_metadata = Field(metadata_name, metadata_id, offset, length)
        self.metadata_name_dict[metadata_name] = metadata_id
        self.metadata_dict[metadata_id] = new_metadata
        
        self.metadata_id_assigned += 1
        return metadata_id
    
    def mod_metadata(self, metadata_name, new_metadata_name, offset, length):
        metadata_id = self.metadata_name_dict[metadata_name]
        self.metadata_dict[metadata_id].modify(new_metadata_name,offset,length)
        return
    
    def get_metadata_by_name(self, metadata_name):
        metadata_id = self.metadata_name_dict[metadata_name]
        return self.metadata_dict[metadata_id]
    
    def get_metadata_by_id(self, metadata_id):
        return self.metadata_dict[metadata_id]
    
    def get_all_metadata(self):
        return self.metadata_dict
    
    def show(self):
        outstr = ''       
        for each_metadata_id in self.metadata_dict.keys():
            outstr += self.metadata_dict.get(each_metadata_id).show()           
        return outstr


class DataTable(object):  #TODO:need to put in the lib
    """
    when delete an element, save the index into the freeList
    alloc a new index from the freeList first; if freeList is empty, use the entryIdNo (then entryIdNo++)
    """
    def __init__(self, start_no):
        self.start_no = start_no
        self.data_table = {}   # id: value (ofp_couter of ofp_meter or ofp_group)
        self.free_id_list = []
        self.entry_id_no = start_no
        self.max_number = sys.maxint
        
    def put(self, index, value):   #index:id, value:ofp_couter of ofp_meter or ofp_group
        if index < 0 or index < self.start_no or index > self.max_number:
            log.error("DataTable.put(): wrong index")   #TODO: throw exception
        self.data_table[index] = value
        
    def get(self, index):
        if index < 0 or index < self.start_no or index > self.max_number:
            log.error("DataTable.get(): wrong index")   #TODO: throw exception
            return None
        else:
            return self.data_table.get(index)
        
    def remove(self, index):
        value = None
        if index < 0 or index < self.start_no or index > self.max_number:
            log.error("DataTable.remove(): wrong index")   #TODO: throw exception
        else:
            value = self.data_table.pop(index)
            self.free_id_list.append(index)
            self.free_id_list.sort()
        return value
    
    def remove_value(self, value):
        for index in self.data_table.keys():
            if self.data_table.get(index) == value:
                self.data_table.pop(index)
                self.free_id_list.append(index)
            
    def alloc(self):
        if len(self.free_id_list) != 0:
            index = self.free_id_list.pop(0)
        else:
            index = self.alloc_new()
        return index
    
    def alloc_new(self):
        if self.entry_id_no > self.max_number:
            return -1
        index = self.entry_id_no
        self.entry_id_no += 1
        return index
    
    def set_max_number(self, max_number):
        if max_number >= 0 and max_number > self.start_no:
            self.max_number = max_number
            
    def get_all_data(self):
        return self.data_table
    
    def get_first_value_index(self, value):
        for index in self.data_table.keys():
            if self.data_table.get(index) == value:
                return index
            
    def used_size(self):
        return len(self.data_table)






class PMSwitchDB(object):
    
    def __init__(self, switch_id):
        self.device_id = switch_id
        self.switch_features_map = {}   #{slot_id: of.ofp_features_reply}
        self.ports_map = {}            #{port_id: ofp_port_status}
        self.ports_name_map = {}    #port_name : port_id
        self.flow_table_resource_map = {}    #{slot_id: ofp_flow_table_resource()}
        self.flow_tables_map = {}            #{global_table_id: ofp_flow_table()}
        self.flow_table_DB_map = {}    #{global_table_id: PMFlowTableDB()}
        self.flow_table_no_base_map = {}     #table_type: NO_base (0 for MM, 8 for LPM, 10 for EM, 16 for LINEAR)
        self.flow_table_no_map = {}
        self.free_flow_table_id_list_map = {}   # ofp_table_type: list[]
        
        self.counter_table = DataTable(COUNTERID_START)
        self.group_table = DataTable(GROUPID_START)
        self.meter_table = DataTable(COUNTERID_START)
        
        self.sended_of_msg_queue = []   # list of ofp
        
    def get_flow_tables_map(self):
        return self.flow_tables_map
    
    def get_flow_entries_map(self, global_table_id):
        table_DB = self.flow_table_DB_map.get(global_table_id)
        if table_DB is None:
            return None
        return table_DB.flow_entries_map
            
    # Flow table functions
    def get_new_flow_table_id(self, table_type):
        new_flow_table_id = FLOWTABLEID_INVALID
        if self.free_flow_table_id_list_map is None or self.free_flow_table_id_list_map.get(table_type) is None or len(self.free_flow_table_id_list_map.get(table_type)) == 0:
            new_flow_table_id = self.flow_table_no_map.get(table_type)
            self.flow_table_no_map[table_type] += 1
        else:
            new_flow_table_id = self.free_flow_table_id_list_map[table_type].pop(0)
        return new_flow_table_id
    
    def add_free_table_id(self, table_type, global_table_id):
        free_id_list = self.free_flow_table_id_list_map.get(table_type)
        if free_id_list is not None:
            free_id_list.append(global_table_id)
            free_id_list.sort()
        else:
            log.error("table is None")
            
    def get_flow_table_DB(self, global_table_id):
        return self.flow_table_DB_map.get(global_table_id)
    
    def set_flow_table_resource(self, flow_table_resource):
        if not isinstance(flow_table_resource, of.ofp_resource_report):
            log.error("wrong table_resource")
            return None
        self.flow_table_resource_map[flow_table_resource.slot_id] = flow_table_resource
        self.counter_table.set_max_number(flow_table_resource.counter_num)
        self.meter_table.set_max_number(flow_table_resource.meter_num)
        self.group_table.set_max_number(flow_table_resource.group_num)
        
    def set_flow_table_no(self, table_type, flow_table_no):
        self.flow_table_no_map[table_type] = flow_table_no
        
    def set_flow_table_no_base(self, table_type, flow_table_no_base):
        self.flow_table_no_base_map[table_type] = flow_table_no_base
        self.free_flow_table_id_list_map[table_type] = []   # FIXME:
    
    def get_flow_table_no_base(self, table_type):
        return self.flow_table_no_base_map.get(table_type)
    
    def get_flow_table_resource_map(self):
        return self.flow_table_resource_map
    
    def get_flow_table_resource(self, slot_id):
        return self.flow_table_resource_map.get(slot_id)
    
    def get_table_number(self, table_type):
        return self.flow_table_no_map.get(table_type) - self.flow_table_no_base_map.get(table_type) - len(self.free_flow_table_id_list_map)
    
    def get_all_table_number(self):
        return len(self.flow_tables_map)
    
    # Counter functions 
    def alloc_counter_id(self):
        new_counter_id = self.counter_table.alloc()
        new_counter = of.ofp_counter(command = of.OFPCC_ADD, counter_id = new_counter_id)     # ofp_counter
        self.counter_table.put(new_counter_id, new_counter)
        return new_counter_id
    
    def remove_counter(self, counter_id):
        return self.counter_table.remove(counter_id)
    
    def set_counter(self, new_counter):
        self.counter_table.put(new_counter.counter_id, new_counter)
    
    def get_counter(self, counter_id):
        return self.counter_table.get(counter_id)
    
    def counter_cmp(self, counter_1, counter_2):  #counter_1 and counter_2 are (ofp_counter)
        if counter_1.counter_id == counter_2.counter_id:
            return 0
        else:
            return 1 if (counter_1.counter_id > counter_2.counter_id) else -1
        
    def get_all_counter_list(self):
        counter_list = []
        data_table = self.counter_table.get_all_data()
        for index in data_table.keys():
            counter_list.append(data_table.get(index))
        return sorted(counter_list, self.counter_cmp)
    
    def get_used_counter_number(self):
        return self.counter_table.used_size()
    
    # Group functions
    def alloc_group_id(self):
        return self.group_table.alloc()
    
    def get_group(self, group_id):  #return a instance of ofp_group_mod
        return self.group_table.get(group_id)
    
    def put_group(self, group_id, group):  #type(group) is ofp_group_mod
        self.group_table.put(group_id, group)
    
    def remove_group(self, group_id):
        return self.group_table.remove(group_id)
    
    def group_cmp(self, group_1, group_2):  #group_1 and group_2 are (ofp_group_mod)
        if group_1.group_id == group_2.group_id:
            return 0
        else:
            return 1 if (group_1.group_id > group_2.group_id) else -1
    
    def get_all_group_list(self):
        group_list = []
        data_table = self.group_table.get_all_data()
        for index in data_table.keys():
            group_list.append(data_table.get(index))
        return sorted(group_list, self.group_cmp)
    
    def get_used_group_number(self):
        return self.group_table.used_size()
    
    # Meter functions
    def alloc_meter_id(self):
        return self.meter_table.alloc()
    
    def get_meter(self, meter_id):  #return a instance of ofp_meter_mod
        return self.meter_table.get(meter_id)
    
    def put_meter(self, meter_id, meter):  #type(meter) is ofp_meter_mod
        self.meter_table.put(meter_id, meter)
    
    def remove_meter(self, meter_id):
        return self.meter_table.remove(meter_id)
    
    def meter_cmp(self, meter_1, meter_2):  #meter_1 and meter_2 are (ofp_meter_mod)
        if meter_1.meter_id == meter_2.meter_id:
            return 0
        else:
            return 1 if (meter_1.meter_id > meter_2.meter_id) else -1
    
    def get_all_meter_list(self):
        meter_list = []
        data_table = self.meter_table.get_all_data()
        for index in data_table.keys():
            meter_list.append(data_table.get(index))
        return sorted(meter_list, self.meter_cmp)
    
    def get_used_meter_number(self):
        return self.meter_table.used_size()
    
    # Port functions
    def put_port(self, port_id, port_status):
        self.ports_map[port_id] = port_status     # ofp_port_status
        self.ports_name_map[port_status.desc.name] = port_id
        
    def del_port(self, port_id):
        self.ports_map.pop(port_id)
        for name in self.ports_name_map:
            if self.ports_name_map[name] == port_id:
                self.ports_name_map.pop(name)     #FIXME: need to be improved
        
    def get_port(self, port_id):
        return self.ports_map.get(port_id)
    
    def get_port_id_by_name(self, port_name):
        return self.ports_name_map.get(port_name)
    
    def get_ports_map(self):
        return self.ports_map

    # Features functions
    def get_switch_features_map(self):
        return self.switch_features_map
    
    def get_switch_features(self, slot_id):
        return self.switch_features_map.get(slot_id)
    
    def set_switch_features(self, slot_id, switch_features):
        if not isinstance(switch_features, of.ofp_features_reply):
            log.error("wrong feature")
            return None
        self.switch_features_map[slot_id] = switch_features
    
    def add_sended_of_message(self, msg):
        if not isinstance(msg, of.ofp_header):
            log.error("Wrong message")
        pass
    
    def get_sended_of_message_queue(self):
        return self.sended_of_msg_queue
    
    def get_sended_of_message(self, xid):
        pass
    
    def delete_sended_of_message(self, xid):
        pass
        
    def add_old_backup_message(self, sended_msg_xid, msg):
        pass
    
    def get_old_backup_message(self, xid):
        pass
    
    def delete_old_backup_message(self, xid):
        pass
    

class PMdatabase(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self)
        self.switch_DB_map = {}   #device_id : PMSwitchDB()
        self.metadata_list = []   #ofp_match20
        self.protocol_name_map = {}   #name(string) : protocol_id(short)
        self.protocol_map = {}    #protocol_id(short):protocol(ofp_protocol)
        self.protocol_no = 0
        self.field_database = {}  #field_id : ofp_match20
        self.field_id_no = 0
        
    # PMSwitchDB functions
    def add_switch_DB(self, switch_id):   # return boolean
        if self.switch_DB_map.get(switch_id) is not None:
            log.error("switch [id = " + str(switch_id) + "] already exists.")
            return False
        self.switch_DB_map[switch_id] = PMSwitchDB(switch_id)
        return True
        
    def get_switch_DB(self, switch_id):
        return self.switch_DB_map.get(switch_id)
        
    def remove_switch_DB(self, switch_id):
        if self.switch_DB_map.get(switch_id) is not None:
            self.switch_DB_map.pop(switch_id)
            
    def get_all_switch_id(self):
        return self.switch_DB_map.keys()
        
    # Protocol functions
    def add_protocol(self, p_name, f_list):
        p_id = self.protocol_no
        t_length = 0
        for f in f_list:
            t_length += f.length
            
        new_protocol = Protocol()
        new_protocol.protocol_name = p_name
        new_protocol.protocol_id = p_id
        new_protocol.total_length = t_length
        new_protocol.field_list = f_list
        
        self.protocol_name_map[p_name] = p_id
        self.protocol_map[p_id] = new_protocol
       
        self.protocol_no += 1
        return p_id
        
    def modify_protocol(self, protocol, f_list):
        if not isinstance(protocol, Protocol):
            return False
        t_length = 0
        for f in f_list:
            t_length += f.length
        protocol.total_length = t_length
        protocol.field_list = f_list
        return True
    
    def del_protocol(self, protocol):
        if not isinstance(protocol, Protocol):
            return False
        self.protocol_name_map.pop(protocol.protocol_name)
        self.protocol_map.pop(protocol.protocol_id)
        return True
    
    def get_protocol_map(self):
        return self.protocol_map
    
    def get_protocol_name_map(self):
        return self.protocol_name_map
    
    #Field functions
    def new_field(self, field_name, offset, length):  # FIXME:??
        field_id = self.field_id_no
        match_field = of.ofp_match20()
        match_field.field_name = field_name
        match_field.field_id = field_id
        match_field.offset = offset
        match_field.length = length
        self.field_database[field_id] = match_field
        self.field_id_no += 1
        log.info("Add Field [field_id] "+ str(field_id) + " [offset] " + str(offset) + " [length] " + str(length) + " [field_name] " + field_name)
        return field_id
    
    def modify_field(self, field_id, field_name, offset, length):
        match_field = self.field_database.get(field_id)
        if match_field is None or not isinstance(match_field, of.ofp_match20):
            return False
        match_field.field_name = field_name
        match_field.offset = offset
        match_field.length = length
        return True
    
    def del_field(self, field_id):
        self.field_database.pop(field_id)
        return True
    
    def get_field_by_id(self, field_id):
        field = self.field_database.get(field_id)
        return field       #FIXME: should be copy
    
    def get_field_by_name(self, field_name):
        match_field_list = []
        for field in self.field_database.values():    # could use iter here
            if field.field_name == field_name:
                match_field_list.append(field)
        field_in_metadata = self.get_metadata_field(field_name)
        if field_in_metadata != None:
            match_field_list.append(field_in_metadata)
        return match_field_list
    
    def field_id_cmp(self, f_1, f_2):  #f_1 and f_2 are fields (ofp_match20)
        if f_1.field_id == f_2.field_id:
            return 0
        else:
            return 1 if (f_1.field_id > f_2.field_id) else -1
    
    def get_all_field(self):
        match_field_list = self.field_database.values()
        return sorted(match_field_list, self.field_id_cmp)
    
    # METADATA functions
    def modify_metadata(self, metadata_list):   #input: a list of ofp_match20 with field=-1
        self.metadata_list = copy.deepcopy(metadata_list)
        
    def get_metadata(self):
        return self.metadata_list
    
    def new_metadata_field(self, field_name, field_offset, field_length):
        """
        if field_offset < 32:
            log.error("wrong offset")
            return None
        """
        if len(self.metadata_list) != 0 and field_offset < (self.metadata_list[-1].offset + self.metadata_list[-1].length):
            log.error("wrong offset")
            return None
        match_field = of.ofp_match20()
        match_field.field_name = field_name
        match_field.field_id = -1
        match_field.offset = field_offset
        match_field.length = field_length
        log.info("Add Metadata [offset] " + str(field_offset) + " [length] " + str(field_length) + " [field_name] " + field_name)
        self.metadata_list.append(match_field)
        
    def get_metadata_field(self, field_name):
        if field_name is None or self.metadata_list is None or len(self.metadata_list) == 0:
            return None
        for field in self.metadata_list:
            if field.field_name == field_name:
                return field
        return None
    
    # Flow Table functions
    def add_flow_table(self, s_id, table_name, table_type, key_length, table_size, field_num, match_field_list):
        switch_DB = self.switch_DB_map.get(s_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return FLOWTABLEID_INVALID
        global_table_id = switch_DB.get_new_flow_table_id(table_type)
        if global_table_id == -1:
            return FLOWTABLEID_INVALID
        if global_table_id == 0 and (table_name != FIRST_ENTRY_TABLE_NAME or table_type != of.OF_MM_TABLE):
            log.error("The first table must be MM table, the name must be " + FIRST_ENTRY_TABLE_NAME)
            return FLOWTABLEID_INVALID
        
        small_table_id = self.parse_to_small_table_id(s_id, global_table_id)
        new_flow_table = of.ofp_flow_table(table_id = small_table_id)
        new_flow_table.table_name = table_name
        new_flow_table.table_type = table_type
        new_flow_table.key_length = key_length
        new_flow_table.table_size = table_size
        new_flow_table.match_field_num = field_num
        new_flow_table.match_field_list = match_field_list
        
        switch_DB.flow_tables_map[global_table_id] = new_flow_table
        switch_DB.flow_table_DB_map[global_table_id] = PMFlowTableDB(flow_table_id = global_table_id)
        return global_table_id
    
    def put_flow_table(self, switch_id, global_flow_table_id, flow_table):
        if not isinstance(flow_table, of.ofp_flow_table):
            return False
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return False
        switch_DB.flow_tables_map[global_flow_table_id] = flow_table
        return True
        
    def get_flow_table(self, switch_id, global_table_id):   #return ofp_flow_table
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.flow_tables_map.get(global_table_id)
    
    def get_flow_table_id(self, switch_id, table_name):   #return global_table_id
        flow_tables_map = self.get_flow_table_map(switch_id)
        #print flow_tables_map
        for table_id in flow_tables_map:
            if flow_tables_map.get(table_id).table_name == table_name:
                return table_id
        return FLOWTABLEID_INVALID
    
    def get_flow_table_map(self, switch_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.flow_tables_map
    
    def delete_flow_table(self, switch_id, table_type, global_table_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is not None:
            switch_DB.flow_tables_map.pop(global_table_id)
            switch_DB.flow_table_DB_map.pop(global_table_id)
            switch_DB.add_free_table_id(table_type, global_table_id)
            
    def get_flow_table_no_base(self, switch_id, table_type):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return FLOWTABLEID_INVALID
        return switch_DB.get_flow_table_no_base(table_type)
        
    def parse_to_small_table_id(self, switch_id, global_table_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return FLOWTABLEID_INVALID
        flow_table = switch_DB.flow_tables_map.get(global_table_id)   # flow_table is an instance of ofp_flow_table
        if flow_table is not None:
            return flow_table.table_id
        for table_type in range(of.OF_MAX_TABLE_TYPE)[::-1]:
            flow_table_no_base = switch_DB.flow_table_no_base_map.get(table_type)
            if flow_table_no_base == FLOWTABLEID_INVALID:
                return flow_table_no_base
            if global_table_id >= flow_table_no_base:
                return global_table_id - flow_table_no_base
        return FLOWTABLEID_INVALID
        
    def parse_to_global_table_id(self, switch_id, table_type, small_table_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return FLOWTABLEID_INVALID
        flow_table_no_base = switch_DB.flow_table_no_base_map.get(table_type)
        if flow_table_no_base == FLOWTABLEID_INVALID:
            return flow_table_no_base
        return flow_table_no_base + small_table_id
        
    # Flow Entry functions
    def add_flow_entry(self, switch_id, global_table_id, match_field_num, matchx_list, instruction_num, instruction_list, priority, counter_enable):
        #flow_entry_id = FLOWENTRYID_INVALID
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return FLOWENTRYID_INVALID
        flow_entry_id = switch_DB.flow_table_DB_map.get(global_table_id).get_new_flow_entry_id()
        table_type = switch_DB.flow_tables_map.get(global_table_id).table_type
        small_table_id = self.parse_to_small_table_id(switch_id, global_table_id)
        new_flow_entry = of.ofp_flow_mod(table_id = small_table_id)
        new_flow_entry.table_type = table_type
        new_flow_entry.index = flow_entry_id
        new_flow_entry.match_field_num = match_field_num
        new_flow_entry.match_list = matchx_list
        new_flow_entry.instruction_num = instruction_num
        new_flow_entry.instruction_list = instruction_list
        new_flow_entry.priority = priority
        #new_counter_id = 0
        if counter_enable == True:
            new_counter_id = self.switch_DB_map.get(switch_id).alloc_counter_id()
            new_flow_entry.counter_id = new_counter_id
        switch_DB.flow_table_DB_map[global_table_id].flow_entries_map[flow_entry_id] = new_flow_entry
        return flow_entry_id
    
    def get_flow_entries_map(self, switch_id, global_table_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_flow_entries_map(global_table_id) #FIXME:
        
    def get_flow_entry(self, switch_id, global_table_id, flow_entry_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        table_DB = switch_DB.flow_table_DB_map.get(global_table_id)
        if table_DB is None or not isinstance(table_DB, PMFlowTableDB):
            return None
        return table_DB.get_flow_entry(flow_entry_id)
    
    def modify_flow_entry(self, switch_id, global_table_id, flow_entry_id, match_field_num, match_list, instruction_num, instruction_list, priority, counter_enable):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return False
        #flow_mod = switch_DB.get_flow_table_DB(global_table_id).get_flow_entry(flow_entry_id)
        flow_mod = self.get_flow_entry(switch_id, global_table_id, flow_entry_id)
        if flow_mod is None or not isinstance(flow_mod, of.ofp_flow_mod):
            return False
        flow_mod.match_field_num = match_field_num
        flow_mod.match_list = match_list
        flow_mod.instruction_num = instruction_num
        flow_mod.instruction_list = instruction_list
        flow_mod.priority = priority
        if counter_enable == True:
            if flow_mod.counter_id == COUNTERID_INVALID:   # no counter before, add counter now
                counter_id = self.get_switch_DB(switch_id).alloc_counter_id()
                flow_mod.counter_id = counter_id
        else:
            if flow_mod.counter_id != COUNTERID_INVALID:
                self.free_counter(switch_id, flow_mod.counter_id)   #free counter
            flow_mod.counter_id = COUNTERID_INVALID
        switch_DB.get_flow_table_DB(global_table_id).flow_entries_map[flow_entry_id] = flow_mod
        return True
    
    def delete_flow_entry(self, switch_id, global_table_id, index):
        flow_entry = self.get_switch_DB(switch_id).get_flow_table_DB(global_table_id).delete_flow_entry(index)
        if flow_entry.counter_id != COUNTERID_INVALID:
            self.free_counter(switch_id, flow_entry.counter_id)
        return flow_entry
        
    # Counter functions
    def allocate_counter(self, switch_id):   # return counter_id
        return self.get_switch_DB(switch_id).alloc_counter_id()   # FIXME:
    
    def free_counter(self, switch_id, counter_id):  # return ofp_counter
        return self.get_switch_DB(switch_id).remove_counter(counter_id)
    
    def set_counter(self, switch_id, new_counter):
        if not isinstance(new_counter, of.ofp_counter):
            return False
        self.get_switch_DB(switch_id).set_counter(new_counter)
        return True
    
    def get_counter(self, switch_id, counter_id):   # return ofp_counter
        return self.get_switch_DB(switch_id).get_counter(counter_id)
    
    def get_all_counters(self, switch_id):   # return a list of ofp_counter
        self.get_switch_DB(switch_id).get_all_counter_list()
    
    def reset_counter(self, switch_id, counter_id):  # return boolean
        counter = self.get_switch_DB(switch_id).get_counter(counter_id)
        if counter is None or not isinstance(of.ofp_counter):
            return False
        counter.counter_id = 0
        counter.counter_value = 0
        self.set_counter(switch_id, counter)
        return True
    
    # Meter functions
    def add_meter_entry(self, switch_id, rate):  # return meter_id (int)
        try:
            switch_DB = self.switch_DB_map.get(switch_id)
            if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
                return False
            meter_id = switch_DB.alloc_meter_id()
            new_meter = of.ofp_meter_mod()
            new_meter.meter_id = meter_id
            new_meter.rate = rate
            switch_DB.put_meter(meter_id, new_meter)
            return meter_id
        except:
            print 'something wrong in pmdatabase.add_meter_entry'
            return METER_INVALID

    def free_meter(self, switch_id, meter_id):  # return ofp_meter_mod
        pass
    
    def get_meter(self, switch_id, meter_id):  # return ofp_meter_mod
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return False
        return switch_DB.get_meter(meter_id)
    
    def modify_meter(self, switch_id, meter_id, rate):  # return boolean
        pass
    
    def get_all_meters(self, switch_id):
        pass
    
    # Group functions
    def add_group_entry(self, switch_id, group_type, action_num, action_list, counter_enable = True):  # return group_id
        pass
    
    def free_group_entry(self, switch_id, group_id):   # return ofp_group_mod
        pass
    
    def get_group_entry(self, switch_id, group_id):   # return ofp_group_mod
        pass
    
    def modify_group_entry(self, switch_id, group_id, group_type, action_num, action_list, counter_enable = True):   # return boolean
        pass
    
    def get_all_groups(self, switch_id):
        pass
    
    # Features function
    def set_features(self, switch_id, feature_reply):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        switch_DB.set_switch_features(feature_reply.slot_id, feature_reply)
        
    def get_features_map(self, switch_id):    # return a map{slot_id: ofp_features_reply}
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_switch_features_map()
    
    def get_features(self, switch_id, slot_id):  # return ofp_features_reply
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_switch_features(slot_id)
    
    # Port functions
    def get_all_port_id(self, switch_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        port_id_list = switch_DB.get_ports_map().keys()
        port_id_list.sort()
        return port_id_list
    
    def set_port_of_enable(self, switch_id, port_id, onoff):
        port_status = self.get_port_status(switch_id, port_id)
        if port_status is not None and port_status.desc is not None:
            port_status.desc.of_enable = onoff
        else:
            log.error("No such port [" + '0x%x' % port_id + ']')
    
    # Port status functions
    def set_port_status(self, switch_id, port_status):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        if not isinstance(port_status, of.ofp_port_status):
            return None
        port_id = port_status.desc.port_id
        switch_DB.put_port(port_id, port_status)
        
    def get_port_status(self, switch_id, port_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_port(port_id)
        
    def del_port_status(self, switch_id, port_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        switch_DB.del_port(port_id)
        
    # Resource report functions
    def set_resource_report(self, switch_id, resource_report):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        if resource_report.resource_type == of.OFRRT_FLOW_TABLE:    # resource_report_type{OFRRT_FLOW_TABLE:0}
            switch_DB.set_flow_table_resource(resource_report)
            self.set_flow_table_no_base(switch_id, resource_report.table_resources_map)
            
    def get_resource_report_map(self, switch_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_flow_table_resource_map()
    
    def get_resource_report(self, switch_id, slot_id):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        return switch_DB.get_flow_table_resource(slot_id)
            
    def set_flow_table_no_base(self, switch_id, flow_table_resource_map):
        switch_DB = self.switch_DB_map.get(switch_id)
        if switch_DB is None or not isinstance(switch_DB, PMSwitchDB):
            return None
        base = 0
        for table_type in range(of.OF_MAX_TABLE_TYPE):                 # OF_MAX_TABLE_TYPE = 4
            table_resource = flow_table_resource_map.get(table_type)   # ofp_table_resource
            switch_DB.set_flow_table_no(table_type, base)   #FIXME:
            switch_DB.set_flow_table_no_base(table_type, base)
            base += table_resource.table_num
            #print switch_DB.get_flow_table_no_base(table_type)   #for test
            
    
    def get_table_number(self, switch_id, table_type):
        return self.get_switch_DB(switch_id).get_table_number(table_type)
    
    def get_all_table_number(self, switch_id):
        return self.get_switch_DB(switch_id).get_all_table_number()
    
    def get_used_counter_number(self, switch_id):
        return self.get_switch_DB(switch_id).get_used_counter_number()
    
    def get_used_group_number(self, switch_id):
        return self.get_switch_DB(switch_id).get_used_group_number()
    
    def get_used_meter_number(self, switch_id):
        return self.get_switch_DB(switch_id).get_used_meter_number()
            
            
            
    def put_match_key(self, switch_id, global_table_id, key_string, entry_id):
        pass
    
    def get_flow_entry_index_by_match_key(self, switch_id, global_table_id, key_string):
        pass
    
    def delete_match_key(self, switch_id, global_table_id, key_string):
        pass
        
        
    # used to roll back
    def add_sended_of_msg(self, switch_id, msg):
        pass
    
    def get_sended_of_msg_queue(self, switch_id):
        pass
    
    def get_sended_of_msg(self, switch_id, xid):
        pass
    
    def delete_sended_of_msg(self, switch_id, msg):
        pass
    
    def add_old_backup_of_msg(self, switch_id, sended_msg_xid, msg):
        pass
    
    def get_old_backup_of_msg(self, switch_id, sended_msg_xid):
        pass
    
    def delete_old_backup_of_msg(self, switch_id, sended_msg_xid):
        pass
        