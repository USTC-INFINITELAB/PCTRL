'''
Created on MAR 11,2017
@author: xyh
'''
from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of
from pox.lib.addresses import IPAddr,EthAddr
import time
import random

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
                  ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP_v4",32), ("DIP_v4",32),("S_Port",16),("D_Port",16 )]
    _add_protocol('ETH_IPv4', field_list)

class Test(EventMixin):
    def __init__ (self):
        add_protocol()
        core.openflow.addListeners(self, priority=0)
        
    def _handle_ConnectionUp (self, event):
        
        match_list=[]
        match_list.append(core.PofManager.get_field("DMAC")[0])
        table_idd=core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_EM_TABLE, 1024, match_list)
        
        match_list=[]
        match_list.append(core.PofManager.get_field("DMAC")[0])
        table_id=core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 1024, match_list)

        #1
        action_list=[]
        ofinstructions=[]
        matchx_list=[]            
        match = core.PofManager.get_field("DMAC")[0]
        temp_matchx = core.PofManager.new_matchx(match, '000000000001', 'FFFFFFFFFFFF')
        matchx_list.append(temp_matchx)     
        action=core.PofManager.new_action_output(0, 0, 0, 0, 0, 0)
        action_list.append(action)             
        ofinstruction=core.PofManager.new_ins_apply_actions(action_list)
        ofinstructions.append(ofinstruction)
        flow_entry_id=core.PofManager.add_flow_entry(event.dpid,table_id,matchx_list,ofinstructions,1,1)    
        
        action_list=[]
        ofinstructions=[]
        matchx_list=[]            
        match = core.PofManager.get_field("DMAC")[0]
        temp_matchx = core.PofManager.new_matchx(match, '000000000002', 'FFFFFFFFFFFF')
        matchx_list.append(temp_matchx)     
        action=core.PofManager.new_action_output(0, 0, 0, 0, 0, 0)
        action_list.append(action)             
        ofinstruction=core.PofManager.new_ins_apply_actions(action_list)
        ofinstructions.append(ofinstruction)
        flow_entry_id=core.PofManager.add_flow_entry(event.dpid,table_id,matchx_list,ofinstructions,2,1)    
        
        '''
        action_list=[]
        ofinstructions=[]
        matchx_list=[]
            
        match = core.PofManager.get_field("DMAC")[0]
        temp_matchx = core.PofManager.new_matchx(match, '000002020202', 'FFFFFFFFFFFF')
        matchx_list.append(temp_matchx)
            
        ofinstruction=core.PofManager.new_ins_goto_table(event.dpid,table_id)
        ofinstructions.append(ofinstruction)
        flow_entry_id=core.PofManager.add_flow_entry(event.dpid,table_idd,matchx_list,ofinstructions,1,1) 
        '''  
def launch ():
    core.registerNew(Test)            

