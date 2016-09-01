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
Created on 2015.8.27

@author: shengrulee
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of

log = core.getLogger()

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

def _handle_PacketIn(event):
    
    table_id = core.PofManager.get_flow_table_id(event.dpid, 'FirstEntryTable')  # 0
    match = core.PofManager.get_field("DMAC")[0]
    temp_matchx = core.PofManager.new_matchx(match, 'ceb7ce59253a', 'FFFFFFFFFFFF')
       
    action_1 = core.PofManager.new_action_output(0, 0, 0, 0, 0x2)  # output
    temp_ins = core.PofManager.new_ins_apply_actions([action_1])
    core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins])
    
    packetout_msg = of.ofp_packet_out()
    packetout_msg.actions.append(of.ofp_action_output(port_id = 2))
    packetout_msg.data = event.ofp
    packetout_msg.in_port = event.port
    event.connection.send(packetout_msg)
    print 'packet out'
    
    table_id = core.PofManager.get_flow_table_id(event.dpid, 'FirstEntryTable')  # 0
    match = core.PofManager.get_field("DMAC")[0]
    temp_matchx = core.PofManager.new_matchx(match, '9e28862bf766', 'FFFFFFFFFFFF')
       
    action_1 = core.PofManager.new_action_output(0, 0, 0, 0, 0x1)  # output
    temp_ins = core.PofManager.new_ins_apply_actions([action_1])
    core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins])
    
#     msg=of.ofp_flow_mod()
#     msg.counter_id = 0
#     msg.cookie = 0
#     msg.cookie_mask = 0
#     msg.table_id = 0
#     msg.table_type = 0 #OF_MM_TABLE
#     #msg.priority = 0
#     msg.index = 0
#   
#     #matchx 1
#     tempmatchx=of.ofp_matchx()
#     tempmatchx.field_id=0
#     tempmatchx.offset=0
#     tempmatchx.length=48
#     tempmatchx.set_value("aaea0e50be91")  #Network Center PC MAC
#     tempmatchx.set_mask("FFffFFffFFff")
#     msg.match_list.append(tempmatchx)
#  
#     tempins=of.ofp_instruction_apply_actions()
#     action = of.ofp_action_output()
#     action.port_id = 1
#     tempins.action_list.append(action)
#     msg.instruction_list.append(tempins)
#     
# 
#     event.connection.send(msg)
# 
#   

# 
# 
#     msg1=of.ofp_flow_mod()
#     msg1.counter_idd = 0
#     msg1.cookie = 0
#     msg1.cookie_mask = 0
#     msg1.table_id = 0
#     msg1.table_type = 0 #OF_MM_TABLE
#     msg1.priority = 0
#     msg1.index = 1
#   
#     #matchx 1
#     #to h2s1
#     tempmatchx1=of.ofp_matchx()
#     tempmatchx1.fieldId=0
#     tempmatchx1.offset=0
#     tempmatchx1.length=48
#     tempmatchx1.set_value("0ad4ca363f87")  #Network Center PC MAC
#     tempmatchx1.set_mask("FFffFFffFFff")
#     msg1.match_list.append(tempmatchx1)
#  
#     tempins1=of.ofp_instruction_apply_actions()
#     action1 = of.ofp_action_output()
#     action1.port_id=2
#     tempins1.action_list.append(action1)
#     msg1.instruction_list.append(tempins1)
#     
# 
#     event.connection.send(msg1)


    log.info("Get PacketIn")
    


def _handle_ConnectionUp(event):
    add_protocol()
    
    core.PofManager.set_port_of_enable(device_id = event.dpid, port_id = 1)
    core.PofManager.set_port_of_enable(device_id = event.dpid, port_id = 2)
    
    core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field("DMAC")[0]])  #0
    

    
        
#     ofmatch20 =of.ofp_match20()
#     ofmatch20.field_id=0
#     ofmatch20.offset=0
#     ofmatch20.length=48
#     
#     first_table = of.ofp_table_mod()
#     first_table.flow_table.table_name='FirstTableEntry'
#     first_table.flow_table.table_id = 0
#     first_table.flow_table.command=0
#     first_table.flow_table.table_type=0
#     first_table.flow_table.table_size=128
#     first_table.flow_table.key_length=48
#     first_table.flow_table.match_field_num=1
#     first_table.flow_table.match_field_list.append(ofmatch20)
#     
#     event.connection.send(first_table)
    
    
def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
