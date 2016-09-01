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

'''
Created on 2015.7.12

@author: Cen
'''
from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of
#from pox.lib.recoco import Timer
#from time import sleep

flow_entry_id_2291=0
dpid_231=2215152430
dpid_230=2215152298
dpid_229=2215146867

device_map = {"SW1": 1,  # 191
              "SW2": 1926449495,  # 192
              #"SW3": 2215152298,  # 230
              #"SW4": 2215152430,  # 231
              }

def _add_protocol(protocol_name, field_list):
    """
    Define a new protocol, and save it to PMDatabase.
    
    protocol_name: string
    field_list:[("field_name", length)]
    """
    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])   #field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("protocol_name", match_field_list)

def add_protocol():
    field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                  ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32)]
    _add_protocol('ETH_IPv4', field_list)
    
    field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_TC_LABLE",32), ("Total_Len",16),
                  ("Protocol",8), ("TTL",8), ("SIP",128), ("DIP",128)]
    _add_protocol('ETH_IPv6', field_list)
    
    field_list = [("DMAC",20), ("SMAC",28)]
    _add_protocol('FFC', field_list)

class Test(EventMixin):
    def __init__ (self):
        add_protocol()
        core.openflow.addListeners(self, priority=0)
        
    def _handle_ConnectionUp (self, event):
        if event.dpid == device_map["SW1"]:
            core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field("DMAC")[0]])  #0
            core.PofManager.add_flow_table(event.dpid, 'Switch', of.OF_LINEAR_TABLE, 32)   # 16
            
            table_id = core.PofManager.get_flow_table_id(event.dpid, 'FirstEntryTable')  # 0
            match = core.PofManager.get_field("DMAC")[0]
            temp_matchx = core.PofManager.new_matchx(match, '0026b954ee0f', 'FFFFFFFFFFFF')
            next_table_id = core.PofManager.get_flow_table_id(event.dpid, 'Switch')  # 16
            temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)    #goto Switch-0
            core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins])
            
            # Switch 16-0
            table_id = core.PofManager.get_flow_table_id(event.dpid, 'Switch')  # 16
            action_1 = core.PofManager.new_action_delete_field(208, 0, 96)    # delete field
            action_2 = core.PofManager.new_action_delete_field(176, 0, 16)    # delete field
            action_3 = core.PofManager.new_action_delete_field(112, 0, 16)    # delete field
            temp_ins_1 = core.PofManager.new_ins_apply_actions([action_1, action_2, action_3])
            temp_ins_2 = core.PofManager.new_ins_goto_direct_table(table_id, 0, 0, 1, None)   #goto Switch-1
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins_1, temp_ins_2])
            # Switch 16-1
            match = core.PofManager.get_field("Eth_Type")[0]
            temp_matchx = core.PofManager.new_matchx(match, '8850', 'FFFF')
            action_1 = core.PofManager.new_action_set_field(temp_matchx)   # set field  
            match = core.PofManager.get_field("DMAC")[0]
            temp_matchx = core.PofManager.new_matchx(match, '200123000021', 'FFFFFFFFFFFF')
            action_2 = core.PofManager.new_action_set_field(temp_matchx)   # set field
            temp_ins_1 = core.PofManager.new_ins_apply_actions([action_1, action_2])
            temp_ins_2 = core.PofManager.new_ins_goto_direct_table(table_id, 0, 0, 2, None)   #goto Switch-2
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins_1, temp_ins_2])
            # Switch 16-2
            action_1 = core.PofManager.new_action_output(0, 0, 0, 0, 0x2)  # output
            temp_ins = core.PofManager.new_ins_apply_actions([action_1])
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins])
            
        if event.dpid == device_map["SW2"]:
            match_1 = core.PofManager.get_field("DMAC")[2]
            match_2 = core.PofManager.get_field("SMAC")[2]
            core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, [match_1, match_2])  #0
            core.PofManager.add_flow_table(event.dpid, 'Switch', of.OF_LINEAR_TABLE, 32)  #16
            
            table_id = core.PofManager.get_flow_table_id(event.dpid, 'FirstEntryTable')  # 0
            matchx_1 = core.PofManager.new_matchx(match_1, '20012', 'FFFFF')
            matchx_2 = core.PofManager.new_matchx(match_2, '3000021', 'FFFFFF')
            next_table_id = core.PofManager.get_flow_table_id(event.dpid, 'Switch')  # 16
            
            temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)    #goto Switch-0
            core.PofManager.add_flow_entry(event.dpid, table_id, [matchx_1, matchx_2], [temp_ins])
            
            # Switch 16-0
            table_id = core.PofManager.get_flow_table_id(event.dpid, 'Switch')  # 16
            action_1 = core.PofManager.new_action_add_field(0, 176, 32, '9bc5138c')  # udp port
            action_2 = core.PofManager.new_action_add_field(0, 176, 64, '0a0000020a000003')  # sip dip
            temp_ins_1 = core.PofManager.new_ins_apply_actions([action_1, action_2])
            temp_ins_2 = core.PofManager.new_ins_goto_direct_table(table_id, 0, 0, 1, None)   #goto Switch-1
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins_1, temp_ins_2])
            # Switch 16-1
            action_1 = core.PofManager.new_action_add_field(0, 160, 16, '4011')
            action_2 = core.PofManager.new_action_add_field(0, 112, 16, '4500')
            temp_ins_1 = core.PofManager.new_ins_apply_actions([action_1, action_2])
            temp_ins_2 = core.PofManager.new_ins_goto_direct_table(table_id, 0, 0, 2, None)   #goto Switch-2
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins_1, temp_ins_2])
            # Switch 16-2
            match = core.PofManager.get_field("Eth_Type")[0]
            temp_matchx = core.PofManager.new_matchx(match, '0800', 'FFFF')
            action_1 = core.PofManager.new_action_set_field(temp_matchx)   # set field  
            match = core.PofManager.get_field("DMAC")[0]
            temp_matchx = core.PofManager.new_matchx(match, '0026b954ee0f', 'FFFFFFFFFFFF')
            action_2 = core.PofManager.new_action_set_field(temp_matchx)   # set field
            temp_ins_1 = core.PofManager.new_ins_apply_actions([action_1, action_2])
            temp_ins_2 = core.PofManager.new_ins_goto_direct_table(table_id, 0, 0, 3, None)   #goto Switch-3
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins_1, temp_ins_2])
            # Switch 16-3
            action_1 = core.PofManager.new_action_output(0, 0, 0, 0, 0x3)  # output
            temp_ins = core.PofManager.new_ins_apply_actions([action_1])
            core.PofManager.add_flow_entry(event.dpid, table_id, [], [temp_ins])
            
    def _handle_PortStatus(self, event):
        #print "yes, its the handle PortStatus fuction"
        port_id = event.ofp.desc.port_id
        port_name = event.ofp.desc.name
        if event.dpid == device_map.get("SW1"):
            if port_id == 0x2 or port_id == 0x3:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == device_map.get("SW2"):
            if port_id == 0x2 or port_id == 0x3:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
            
def counter(sw_name, global_table_id, entry_id):   #sw_name:string
    device_id = device_map[sw_name]
    counter_id = core.PofManager.get_flow_entry(device_id, global_table_id, entry_id).counter_id
    core.PofManager.query_counter_value(device_id, counter_id)


def launch ():
    core.registerNew(Test)
    #Timer(25,change,recurring=False)
