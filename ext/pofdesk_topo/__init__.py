
"""
This allows you to easily run POFDesk.
"""
from BaseHTTPServer import *
from pox.core import core
import pox.openflow.libpof_02 as of
import os.path
from pox.web.webcore import *
import cgi
import template
from pox.lib.util import dpidToStr
#from gui_to_pofmanager import *
import string
from pox.lib.revent.revent import EventMixin
from setuptools.command.build_ext import if_dl
###################################################################
global links
global protocol#just to sava a protocol
global protocols#to save all protocols
global protocol_name
global offset
global Metadata
global Table_entry
global Flow_entry_list
global ports
global showflowentrys
global showtables
global Tables
global Table
Tables={}
Table={}
ports=[]
Flow_entry_list={}
Metadata=[]
offset=0
protocol=[]
protocols={}
protocol_name=""
Table_entry={}
Flow_entry_list={}
showflowentrys={}
showtables={}
###################################################
protocols={'ETH':[('Dmac', 48, 0), ('Smac', 48, 48), ('Type', 16, 96)],
           'ETH+IPv6':[('Dmac', 48, 0), ('Smac', 48, 48), ('Type', 16, 96),('V', 4, 112), ('TC', 8, 116), ('Label', 20, 124),('Totallength',16,144),('NH',8,160),('TTL',8,168),('SIP',128,176),('DIP',128,304)],
           'ETH+IPv4':[('Dmac', 48, 0), ('Smac', 48, 48), ('Type', 16, 96), ('V', 4, 112), ('IHL', 4, 116), ('TOS', 8, 120), ('TotalLength', 16, 128), ('ID', 16, 144), ('Flag', 16, 160), ('TTL', 8, 176), ('Protocol', 8, 184), ('checksum', 16, 192), ('SIP', 32, 208), ('DIP', 32, 240)],
           }
###################################################################
'''
this class aims to define the relationship between webpath and local path
'''
class POFdesk(EventMixin):
    #httpd = core.WebServer
    def __init__ (self):
          
        global links
        links=set()
        #core.listen_to_dependencies(self)
        core.openflow.addListeners(self)
        httpd = core.WebServer
        local_path=path_prase('template')
        www_path="/Spectrum/"
        httpd.set_handler(www_path, slothandler,
                          {'root':local_path}, True);#set handler
        www_path="/topo/"
        httpd.set_handler(www_path,topohandler,
                     {'root':local_path}, True);
        www_path="/protocol/"
        httpd.set_handler(www_path,protocolhandler,
                     {'root':local_path}, True);
        www_path="/table/"
        httpd.set_handler(www_path,tablehandler,
                     {'root':local_path}, True);
        www_path="/port/"
        httpd.set_handler(www_path,porthandler,
                      {'root':local_path},True)
        local_path=path_prase('data')
        httpd.set_handler("/data", StaticContentHandler, {'root':local_path}, True)
        for key in protocols.keys():
            match_field_list = []
            field_list=[]
            for field in protocols[key]:
                field_id = core.PofManager.new_field(field[0], field[2], field[1])
                match_field_list.append(core.PofManager.get_field(field_id))
                field_tuple=(field[0], field[1], field[2],field_id)
                field_list.append(field_tuple)
            core.PofManager.add_protocol(key,match_field_list)
            protocols[key]=field_list
        print "the url has been built!--hdyaaaaa"
    def _handle_ConnectionUp (self, event):
        global Flow_entry_list
        ss=dpidToStr(event.dpid)
        Tables[ss]=[]
        Flow_entry_list[ss]=[]
    def _handle_ConnectionDown (self, event):
        global Flow_entry_list
        global ports
        ss=dpidToStr(event.dpid)
        Tables.pop(ss)
        Flow_entry_list.pop(ss)
        for port in ports:
            if port[0]==ss:
                ports.remove(port)
    
    def _handle_PortStatus (self, event):
        """
        Track changes to switch ports
        """
        #print "handle_portstatus!"
        global ports
        mac=dpidToStr(event.dpid)
        ports.append((mac,event.port))
           
    def _handle_openflow_discovery_LinkEvent (self, event):
        #find topolink!
        global links
        s1 = event.link.dpid1
        s2 = event.link.dpid2
        if s1 > s2: s1,s2 = s2,s1
        s1 = dpidToStr(s1)
        s2 = dpidToStr(s2)
        if event.added:
            links.add((s1,s2))
        elif event.removed and (s1,s2) in links:
            links.remove((s1,s2))

def path_prase(local_path):
#find the real path
    import inspect
    path = inspect.stack()[1][1]
    path = os.path.dirname(path)
    local_path = os.path.join(path, local_path)
    local_path = os.path.abspath(local_path)
    #print local_path
    return local_path
    
def OnlyStr(s,oth=''):
    s=str(s)
    fomart = 'abcdefghijklmnopqrstuvwxyz0123456789'
    for c in s:
        if not c in fomart:
            s = s.replace(c,'');
    return s;  
    
# class topohandler(StaticContentHandler):
#     """
#     topology page handler
#     """
#     def do_GET (self): 
#         ovs_switches=[]
#         for switch in core.PofManager.switches.keys():
#             ovs_switches.append(dpidToStr(switch))
#         global links
#         if self.path.startswith('/static/'):
#             SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self) #load static source
#         else:
#                     x=("111","42","126","184","412","291","681","418","540","669","675","876","896","766")
#                     y=("45","202","351","193","379","274","392","234","209","191","43","46","227","306")    
#                     i=0
#                     jsonStr=""
#                     for switch in ovs_switches:
#                         #m_dpid= str(dpid)
#                         m=x[i]
#                         n=y[i]
#                         if i==0:
#                             jsonStr+='{"devices":[{"id":"'+switch+'","name":"switch ","src":"static/img/Router_Icon_128x128.png","x":'+m+',"y":'+n+',"width":80,"height":50}'
#                             i+=1
#                         else:
#                             jsonStr+=',{"id":"'+switch+'","name":"switch ","src":"static/img/Router_Icon_128x128.png","x":'+m+',"y":'+n+',"width":80,"height":50}'
#                             i+=1
#                     jsonStr+=']'
#                     i=0
#                     if links:
#                         for link in links:
#                             if i == 0:
#                                 jsonStr+=',"lines":[{"srcDeviceId":"'+link[0]+'","dstDeviceId":"'+link[1]+'","stroke":"black","strokeWidth":3}'
#                                 i+=1
#                             else:
#                                 jsonStr+=',{"srcDeviceId":"'+link[0]+'","dstDeviceId":"'+link[1]+'","stroke":"black","strokeWidth":3}'
#                                 i+=1
#                         jsonStr+=']}'
#                     else:
#                         jsonStr+='}'
#                     path=path_prase('template')
#                     render = template.render(path)
#                     s=render.topo(jsonStr)
#                     s=str(s)
#                     s=s.replace('&quot;', '"')#translate &quot into "
#                     self.send_response(200)
#                     self.send_header('Content-type','text/html')
#                     self.end_headers()
#                     self.wfile.write(s)
#     def do_POST (self):
#         #print post_content
#         self.form = cgi.FieldStorage(
#         fp=self.rfile,
#         headers=self.headers,
#         environ={'REQUEST_METHOD':'POST',
#             'CONTENT_TYPE':self.headers['Content-Type'],
#             })

class topohandler(StaticContentHandler):
  """
  topology page handler
  """
  def do_GET (self): 
         
        global links
        print "it is topo get"
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        if self.path.startswith('/static/'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self) #load static source
        else:   
            i=0
            jsonStr=""
            for switch in ovs_switches:
                if i==0:
                    jsonStr+='{"device":[{"id":"'+switch+'"}'
                    i+=1
                else:
                    jsonStr+=',{"id":"'+switch+'"}'
                    i+=1
            jsonStr+=']'
            i=0
            if links:
                for link in links:
                    if i == 0:
                        jsonStr+=',"links":[{"source":"'+link[0]+'","target":"'+link[1]+'"}'
                        i+=1
                    else:
                        jsonStr+=',{"source":"'+link[0]+'","target":"'+link[1]+'"}'
                        i+=1
                jsonStr+=']}'
            else:
                jsonStr+='}'   
            path=path_prase('template')
            render = template.render(path)
            s=render.topology(jsonStr)
             
            s=str(s)
            s=s.replace('&quot;', '"')#translate &quot into "
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(s)
                    
  def do_POST (self):
    #print post_content
    form = cgi.FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={'REQUEST_METHOD':'POST',
          'CONTENT_TYPE':self.headers['Content-Type'],
          })
    print form.getvalue('post_content')


class protocolhandler(StaticContentHandler):
    """
    topology page handler
    """
    def do_GET(self):
        global protocols
        global protocol
        global protocol_name
        global offset
        global Metadata
        global Table_entry
        global Flow_entry_list
        global ports
        global showtables
        global Tables
        global Table
        fields=core.PofManager.get_metadata()
        fields=fields+core.PofManager.get_all_field()   
        self.Operation_argument={}
        self.Operation_argument['save_flag']=0
        self.Operation_argument['table_error']=0
        self.Operation_argument["add_entry_error--the number of instructions beyond 6!"]=0
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
#         for field in core.PofManager.get_all_field():
#             fields.append(field)
        if self.path.startswith('/static/'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self) #load static source
        else:
            path=path_prase('template')
            render = template.render(path)
            s=render.protocol(self.Operation_argument,protocols,protocol,protocol_name,ovs_switches,Table_entry,Metadata,Flow_entry_list,ports,Tables,Table,fields)           
            s=str(s)
            s=s.replace('&quot;', '"')#translate &quot into "
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(s) 
    def do_POST (self):
        global protocols
        global protocol
        global Metadata
        global protocol_name
        global offset
        global Table_entry
        global Flow_entry_list
        global ports
        global showtables
        global Tables
        global Table
        fields=core.PofManager.get_metadata()
        fields=fields+core.PofManager.get_all_field()       
        self.Operation_argument={}
        self.Operation_argument['save_flag']=0
        self.Operation_argument['table_error']=0
        self.Operation_argument["add_entry_error--the number of instructions beyond 6!"]=0
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        print "it's a post"
        #print post_content
        form = cgi.FieldStorage(
          fp=self.rfile,
          headers=self.headers,
          environ={'REQUEST_METHOD':'POST',
              'CONTENT_TYPE':self.headers['Content-Type'],
              })
##############to save the fields###############################
        if(form.getvalue('fieldname') and form.getvalue('fieldlength')):
            name=form.getvalue('fieldname')
            length=int(form.getvalue('fieldlength'))
            field=(name,length,offset)
            protocol.append(field)
            offset+=length
##############t#to process the operation of the field###############################
        if(form.getvalue('fielddelete')):
            protocol=[]
            offset=0
##############to save the protocol###############################
        if(form.getvalue('saveprotocol') and form.getvalue('protocolname') and protocol):
            if (form.getvalue('protocolname').lower()=='metadata'):
                Metadata=protocol
                match_field_list=[]
                for field in protocol:
                    core.PofManager.new_metadata_field(field[0], field[2], field[1])
            else:
                match_field_list = []
                field_list=[]
                for field in protocol:
                    field_id = core.PofManager.new_field(field[0], field[2], field[1])
                    match_field_list.append(core.PofManager.get_field(field_id))
                    field_tuple=(field[0], field[2], field[1],field_id)
                    field_list.append(field_tuple)
                protocol_id=core.PofManager.add_protocol(form.getvalue('protocolname'),match_field_list)
                protocols[form.getvalue('protocolname')]=field_list
            protocol=[]
            offset=0
##############to process the operation of the protocol
        if(form.getvalue("saveoperation")):
            for key in protocols.keys():
                if(form.getvalue(key)=="delete"):
                    protocols.pop(key)
                    protocol_name_map = self.database.get_protocol_name_map()
                    if protocol_name_map is None:
                        break
                    protocol_id = protocol_name_map.get(protocol_name)
                    core.PofManager.del_protocol(protocol_id)
                    if protocol_name==key:
                        protocol_name=""
                        Table={}
                        Table_entry={}
                if(form.getvalue(key)=="add table"):
                    if(Table):
                        if(Table['protocol']!=key):
                            Table={}
                            Table_entry={}
                    protocol_name=key
                    
###************to process add table****************************************************
        if(form.getvalue('table')):
            switch_id=form.getvalue('device')
            #print switch_id
            Table_name=form.getvalue('Table_name')
            Table_type=form.getvalue('Table_type')
            size=form.getvalue('Table_Size')
            size=int(size)
            Table_field=form.getvalue('Table_field')
            device_id=OnlyStr(form.getvalue('device'))
            device_id=int(device_id,16)
            Table_field=eval(Table_field)
            if Table_type=="OF_MM_TABLE":
                table_type=0
            if Table_type=="OF_LPM_TABLE":
                table_type=1
            if Table_type=="OF_EM_TABLE":
                table_type=2
            if Table_type=="OF_LINEAR_TABLE":
                table_type=3
                Table_field=[]
            table={}
            table['name']=Table_name
            table['type']=table_type
            table['type_show']=Table_type
            table['size']=size
            table['protocol']=protocol_name
            table['switch_id']=switch_id
            table['field']=Table_field
            table['global_id']=GUI_add_table(table)
            Tables[switch_id].append(table)
##************* table operation (add flow entry or delete table)*********************************************************
        if(form.getvalue('savetableoperation')):
            if(form.getvalue('tableresult')=="Add table entry"):
                print "add table entry"
                Table=form.getvalue('usetable')
                Table=eval(Table)
                Table_entry={}
                    
##*************delete table*********************************************************
            if(form.getvalue('tableresult')=="Delete table"):
                print "Delete table"
                Table=form.getvalue('table_id')
                Table=eval(Table)
                

###************to process the tablematch*********************************
        if(form.getvalue('tablematch')):
            print "add table match!"
            entry_priority=form.getvalue('Table_priority')
            entry_priority=int(entry_priority)
            counter_enable=form.getvalue("Counter_Enable")
            counter_enable=int(counter_enable)
            if counter_enable==1:
                counter_enable=True
            else:
                counter_enable=False
            field_list=[]
            for field in Table["field"]:
                value=form.getvalue(field['name']+'_value')
                mask=form.getvalue(field['name']+'_mask')
                field['value']=value
                field['mask']=mask
                field_list.append(field)
            Table_entry['switch_id']=Table['switch_id']
            Table_entry['field_list']=field_list      
            Table_entry['priority']=entry_priority
            Table_entry['counter_enable']=counter_enable
            Table_entry['instruction']=[]
            Table_entry['table_global_id']=Table["global_id"]
            Table_entry['table_type']=Table["type"]
            Table_entry['protocol']=Table["protocol"]
###################to add table entry########################################
        if(form.getvalue('addtableentrysubmit')):
            instructions=form.getvalue('submitinstruction')
            instructions=eval(instructions)
            (self.Operation_argument["add_entry_error--the number of instructions beyond 6!"],entry_id)=GUI_add_flowentry(Table_entry,instructions)
            if self.Operation_argument["add_entry_error--the number of instructions beyond 6!"]==0:
                Table_entry['instructions']=instructions   
                Table_entry['entry_id']=entry_id                     
                Flow_entry_list[Table['switch_id']].append(Table_entry)
        if(form.getvalue('load')):
            for switch_id in core.PofManager.switches.keys():
                core.PofManager.del_all_flow_tables(switch_id)
            #core.PofManager.del_all_protocol()
            datafile = form.getvalue('datafile')
            datafile=eval(datafile)
            protocols = datafile['protocols']
            Metadata = datafile['Metadata']
            for field in Metadata:
                    core.PofManager.new_metadata_field(field[0], field[2], field[1])
            for key in protocols.keys():
                if key=="ETH" or key=="ETH+IPv4" or key=="ETH+IPv6":
                    break
                else:
                    match_field_list = []
                    field_list=[]
                    for field in protocols[key]:
                        field_id = core.PofManager.new_field(field[0], field[2], field[1])
                        match_field_list.append(core.PofManager.get_field(field_id))
                        field_tuple=(field[0], field[1], field[2],field_id)
                        field_list.append(field_tuple)
                    core.PofManager.add_protocol(key,match_field_list)
                    protocols[key]=field_list
            Tables= datafile['Tables']
            for key in Tables.keys():
                for table in Tables[key]:
                    print table
                    GUI_add_table(table)
                    #add_new_table(device_id, table)
            Flow_entry_list= datafile['Flow_entry_list']
            for key in Flow_entry_list.keys():
                for table in Flow_entry_list[key]:
                    switch=OnlyStr(key)
                    switch=int(switch,16)
                    GUI_add_flowentry(table, table['instructions'])
        if(form.getvalue('save')):
            f={}
            f['protocols']=protocols
            f['Metadata']=Metadata
            f['Tables']=Tables
            f['Flow_entry_list']=Flow_entry_list
            f=str(f)
            path=path_prase('data/data.db')
            self.file=open(path,'w')
            self.file.write(f)
            self.file.close()
            self.Operation_argument['save_flag']=1
###################to send message to HTML#################################
        path=path_prase('template')
        render = template.render(path)
        f=render.protocol(self.Operation_argument,protocols,protocol,protocol_name,ovs_switches,Table_entry,Metadata,Flow_entry_list,ports,Tables,Table,fields)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f)
class tablehandler(StaticContentHandler):
    """
    topology page handler
    """
    def do_GET(self):
        print "it's a get"
        global showflowentrys
        global showtables
        global Tables
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        if self.path.startswith('/static/'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self) #load static source
        else:
            showflowentrys=Flow_entry_list
            showtables=Tables
            print showflowentrys
            path=path_prase('template')
            render = template.render(path)
            s=render.table(showflowentrys,ovs_switches,protocols,showtables)           
            s=str(s)
            s=s.replace('&quot;', '"')#translate &quot into "
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(s)
    def do_POST (self):
        global protocols
        global Flow_entry_list
        global showflowentrys
        global Tables
        global showtables
        print "it's a post"
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        #print post_content
        form = cgi.FieldStorage(
          fp=self.rfile,
          headers=self.headers,
          environ={'REQUEST_METHOD':'POST',
              'CONTENT_TYPE':self.headers['Content-Type'],
              })
        if form.getvalue('search'):
            device=form.getvalue('switch')
            protocolname=form.getvalue('protocol')
            showflowentrys={}
            showtables={}
            if device and protocolname:
                tableentrys=Flow_entry_list[device]
                table=Tables[device]
                showflowentrys[device]=[]
                showtables[device]=[]
                for tableentry in tableentrys:
                    if tableentry['protocol']==protocolname:
                        showflowentrys[device].append(tableentry)
                for m in table:
                    if m['protocol']==protocolname:
                        showtables[device].append(m)
            elif device and not protocolname:
                tableentrys=Flow_entry_list[device]
                table = Tables[device]
                showflowentrys[device]=[]
                showflowentrys[device]=tableentrys
                showtables[device]=[]
                showtables[device]=table
            elif not device and protocolname:
                for key in Flow_entry_list:
                    showflowentrys[key]=[]
                    for flowentry in Flow_entry_list[key]:
                        if flowentry['protocol']==protocolname:
                            showflowentrys[key].append(flowentry)
                for key in Tables:
                    showtables[key]=[]
                    for m in Tables[key]:
                        if m['protocol']==protocolname:
                            showtables[key].append(m)
            else:
                showflowentrys=Flow_entry_list
                showtables=Tables
        
        if form.getvalue('table_delete'):
            print "delete table"
            deviceid=form.getvalue("device_id")
            tableid=int(form.getvalue('table_id'))
            i=0
            self.list=[]
            for table in Flow_entry_list[deviceid]:
                if tableid==table['table_global_id']:
                    self.list.append(i)
                i+=1
            self.list.reverse()
            for i in self.list:
                del Flow_entry_list[deviceid][i]
            
            for table in Tables[deviceid]:
                device_id=OnlyStr(deviceid)
                device_id=int(device_id,16)
                if tableid==table['global_id']:
                    table_id=tableid
                    print device_id,tableid
                    core.PofManager.del_flow_table_and_all_sub_entries(device_id,tableid)
                    Tables[deviceid].remove(table)

        
        if form.getvalue('entry_delete'):
            print "delete table entry"
            device_id=form.getvalue('entry_id')
            for tableentry in Flow_entry_list[device_id]:
                tableid=tableentry['table_global_id']
                entryid=tableentry['entry_id']
                if int(form.getvalue('table_id'))==tableid and int(form.getvalue('entry_id'))==entryid:
                    Flow_entry_list[device_id].remove(tableentry)
                    device_id=OnlyStr(device_id)
                    device_id=int(device_id,16)
                    table_id=tableid
                    entry_id=entryid
                    core.PofManager.delete_flow_entry(device_id,table_id, entry_id)
                    break
        if form.getvalue('delete_all_tables'):
            print "delete_all_tables"
            for switch_id in core.PofManager.switches.keys():
                core.PofManager.del_all_flow_tables(switch_id)
                switch_id=dpidToStr(switch_id)
                Flow_entry_list[switch_id]=[]
                Tables[switch_id]=[]
                    
        if form.getvalue('delete_all_entries'):
            print "delete_all_entries"
            for key in Flow_entry_list.keys():
                for flowentry in Flow_entry_list[key]:
                    device_id=OnlyStr(key)
                    device_id=int(device_id,16)
                    tableid=flowentry['table_global_id']
                    entryid=flowentry['entry_id']
                    entry_id=int(entryid)
                    table_id=tableid
                    core.PofManager.delete_flow_entry(device_id, table_id, entry_id)
                Flow_entry_list[key]=[]
            showflowentrys={}
            
        if form.getvalue('delete_show_tables'):
            print "delete_show_tables"
            for key in showflowentrys.keys():
                i=len(showflowentrys[key])
                while(i):
                    i=i-1
                    del showflowentrys[key][i]
            showflowentrys={}
            for key in showtables.keys():
                for table in showtables[key]:
                    device_id=OnlyStr(key)
                    device_id=int(device_id,16)                    
                    tableid=table['global_id']
                    table_id=tableid
                    core.PofManager.del_flow_table_and_all_sub_entries(device_id, table_id)
            for key in showtables.keys():
                i=len(showtables[key])
                while(i):
                    i=i-1
                    del showtables[key][i]
            showtables={}
            

        if form.getvalue('delete_show_entries'):
            print "delete_show_entries"
            for key in showflowentrys.keys():
                for flowentry in showflowentrys[key]:
                    device_id=OnlyStr(key)
                    device_id=int(device_id,16)
                    tableid=flowentry['table_global_id']
                    entryid=flowentry['entry_id']
                    entry_id=int(entryid)
                    table_id=int(tableid)
                    core.PofManager.delete_flow_entry(device_id, table_id, entry_id)
            for key in showflowentrys.keys():
                i=len(showflowentrys[key])
                while(i):
                    i=i-1
                    del showflowentrys[key][i]
            showflowentrys={}                 
            
            
        path=path_prase('template')
        render = template.render(path)
        f=render.table(showflowentrys,ovs_switches,protocols,showtables)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f)
class porthandler(StaticContentHandler):
    def do_GET(self):
        print "it is port get"
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        jsonStr=""
        if self.path.startswith('/static'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        else:
            jsonStr='{'
            i=0
            for switch in ovs_switches:
                device_id=OnlyStr(switch)
                device_id=int(device_id,16)
                ports=core.PofManager.get_all_port_id(device_id)
                if(i==0):
                    jsonStr+='"'+switch+'":'
                    i+=1
                else:
                    jsonStr+=',"'+switch+'":' 
                j=0
                for p in ports:
                    status=core.PofManager.get_port_status(device_id,p)
                    if j==0:
                        jsonStr+='[{"deviceId":"'+switch+'","portId":"'+str(status.desc.port_id)+'","hardwareAddress":"'+str(status.desc.hw_addr)+'","name":"'+str(status.desc.name)+'","config":"'+str(status.desc.config)+'","state":"'+str(status.desc.state)+'","currentFeatures":"'+str(status.desc.curr)+'","advertisedFeatures":"'+str(status.desc.advertised)+'","supportedFeatures":"'+str(status.desc.supported)+'","peerFeatures":"'+str(status.desc.peer)+'","currentSpeed":"'+str(status.desc.curr_speed)+'","maxSpeed":"'+str(status.desc.max_speed)+'","openflowEnable":"'+str(status.desc.of_enable)+'"}'
                        j+=1
                    else:
                        jsonStr+=',{"deviceId":"'+switch+'","portId":"'+str(status.desc.port_id)+'","hardwareAddress":"'+str(status.desc.hw_addr)+'","name":"'+str(status.desc.name)+'","config":"'+str(status.desc.config)+'","state":"'+str(status.desc.state)+'","currentFeatures":"'+str(status.desc.curr)+'","advertisedFeatures":"'+str(status.desc.advertised)+'","supportedFeatures":"'+str(status.desc.supported)+'","peerFeatures":"'+str(status.desc.peer)+'","currentSpeed":"'+str(status.desc.curr_speed)+'","maxSpeed":"'+str(status.desc.max_speed)+'","openflowEnable":"'+str(status.desc.of_enable)+'"}'
                jsonStr+=']'
            jsonStr+='}'
        path=path_prase('template')
        render = template.render(path)
        try:
            s=render.port(jsonStr,ovs_switches)
            s=str(s)
            s=s.replace("&#39;","'")
            s=s.replace('&quot;','"')
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(s)
        except Exception:
            self.wfile._sock.close()
            self.wfile._sock=None
    def do_POST (self):
        print "Ports--POST"
        form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST',
                'CONTENT_TYPE':self.headers['Content-Type'],
                })
        print form.getvalue('switch_id')
        print form.getvalue('port_id')
        device_id=OnlyStr(form.getvalue('switch_id'))
        device_id=int(device_id,16)
        port_id=int(form.getvalue('port_id'))
        status=form.getvalue('onoff')
        if status=="0":
            onoff=True
        elif status=="False":
            onoff=True
        else:
            onoff=False
        core.PofManager.set_port_of_enable(device_id, port_id, onoff)
        ovs_switches=[]
        for switch in core.PofManager.switches.keys():
            ovs_switches.append(dpidToStr(switch))
        jsonStr=""
        if self.path.startswith('/static'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        else:
            jsonStr='{'
            i=0
            for switch in ovs_switches:
                device_id=OnlyStr(switch)
                device_id=int(device_id,16)
                ports=core.PofManager.get_all_port_id(device_id)
                if(i==0):
                    jsonStr+='"'+switch+'":'
                    i+=1
                else:
                    jsonStr+=',"'+switch+'":' 
                j=0
                for p in ports:
                    status=core.PofManager.get_port_status(device_id,p)
                    if j==0:
                        jsonStr+='[{"deviceId":"'+switch+'","portId":"'+str(status.desc.port_id)+'","hardwareAddress":"'+str(status.desc.hw_addr)+\
                        '","name":"'+str(status.desc.name)+'","config":"'+str(status.desc.config)+'","state":"'+str(status.desc.state)+\
                        '","currentFeatures":"'+str(status.desc.curr)+'","advertisedFeatures":"'+str(status.desc.advertised)+\
                        '","supportedFeatures":"'+str(status.desc.supported)+'","peerFeatures":"'+str(status.desc.peer)+'","currentSpeed":"'\
                        +str(status.desc.curr_speed)+'","maxSpeed":"'+str(status.desc.max_speed)+'","openflowEnable":"'+str(status.desc.of_enable)+'"}'
                        j+=1
                    else:
                        jsonStr+=',{"deviceId":"'+switch+'","portId":"'+str(status.desc.port_id)+'","hardwareAddress":"'+str(status.desc.hw_addr)+'","name":"'+str(status.desc.name)+'","config":"'+str(status.desc.config)+'","state":"'+str(status.desc.state)+'","currentFeatures":"'+str(status.desc.curr)+'","advertisedFeatures":"'+str(status.desc.advertised)+'","supportedFeatures":"'+str(status.desc.supported)+'","peerFeatures":"'+str(status.desc.peer)+'","currentSpeed":"'+str(status.desc.curr_speed)+'","maxSpeed":"'+str(status.desc.max_speed)+'","openflowEnable":"'+str(status.desc.of_enable)+'"}'
                jsonStr+=']'
            jsonStr+='}'
        path=path_prase('template')
        render = template.render(path)
        try:
            s=render.port(jsonStr,ovs_switches)
            s=str(s)
            s=s.replace("&#39;","'")
            s=s.replace('&quot;','"')
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(s)
        except Exception:
            self.wfile._sock.close()
            self.wfile._sock=None
class slothandler(StaticContentHandler):
    """
    A test page for POFdesk.
    """
    def do_GET (self):
        self.slot="0000000000111111111110101010111111111111100000000000"
        if self.path.startswith('/static/'):
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self) #load static source
        else:
            path=path_prase('template')
            render = template.render(path)
            f=render.slot(self.slot)
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(f)

    def do_POST (self):
        self.slot="0000000000111111111110101010111111111111100000000000"
        self.form = cgi.FieldStorage(
          fp=self.rfile,
          headers=self.headers,
          environ={'REQUEST_METHOD':'POST',
              'CONTENT_TYPE':self.headers['Content-Type'],
              })
        path=path_prase('template')
        render = template.render(path)
        f=render.slot(self.slot)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f)
def GUI_add_table(table):
    match_field_list=[]
    device_id=OnlyStr(table['switch_id'])
    device_id=int(device_id,16)
    for field in table['field']:
        if field["field_id"]==-1:
            match_field=core.PofManager.get_metadata_field(field["name"])
        else:
            match_field=core.PofManager.get_field(field["field_id"])
        print match_field
        match_field_list.append(match_field)   
    return core.PofManager.add_flow_table(device_id, table['name'], table['type'], table['size'], match_field_list)
def GUI_add_flowentry(Table_entry,instructions):
    ofinstructions=[]
    action_list=[]
    #print instructions
    matchx_list=[]
    for field in Table_entry['field_list']:
        matchx=of.ofp_matchx()
        matchx.field_id=field["field_id"]
        matchx.field_name=field["name"]
        matchx.length=field["length"]
        matchx.offset=field["offset"]
        matchx.mask=field['mask']
        matchx.value=field['value']
        matchx_list.append(matchx)
    for instruction in instructions:
        ofinstruction=None
        if instruction['action']=="apply_action":
            print "instruction--apply-action"
            if len(action_list)>6:
                ofinstruction=core.PofManager.new_ins_apply_actions(action_list)
                action_list=[]
            if instruction['action_type']=="output":
                print "instruction--apply-action--output!"
                port_id_value_type=int(instruction["port_value_type"])
                if instruction["metadata_offset"]:
                    metadata_offset=int(instruction["metadata_offset"])
                else:
                    metadata_offset=0
                if instruction["metadata_length"]:
                    metadata_length=int(instruction["metadata_length"])
                else:
                    metadata_length=0
                if instruction["packet_offset"]:
                    packet_offset=int(instruction["packet_offset"])
                else:
                    packet_offset=0
                if port_id_value_type==0:
                    port_id=int(instruction["portid_value"])
                    port_id_field=None
                else:
                    port_id=0
                    port_id_field_id=int(string.split(instruction["portid_field"],':')[0])
                    if port_id_field_id==-1:
                        port_id_field_name=string.split(instruction["portid_field"],':')[1]
                        port_id_field=core.PofManager.get_metadata_field(port_id_field_name)
                    else:
                        port_id_field=core.PofManager.get_field(port_id_field_id)
                action=core.PofManager.new_action_output(port_id_value_type, metadata_offset, metadata_length, packet_offset, port_id, port_id_field)
                action_list.append(action)
                
            if instruction['action_type']=="set_field":
                print "instruction--apply-action--setfield!"
                field_name=string.split(instruction["name"],';')[0]
                for field_tuple in protocols[protocol_name]:
                    if field_name==field_tuple[0]:
                        field_id=field_tuple[3]
                        break
                field=core.PofManager.get_field(field_id)
                field_setting=of.ofp_matchx()
                field_setting.field_id=field.field_id
                field_setting.field_name=field.field_name
                field_setting.offset=field.offset
                field_setting.length=field.length
                field_setting.value=instruction["value"]
                field_setting.mask=instruction["mask"]
                print field_setting
                action=core.PofManager.new_action_set_field(field_setting)
                action_list.append(action)
                    
            if instruction['action_type']=="set_field_from_metadata":
                print "instruction--apply-action--set_field_from_metadata!"
                metadata_offset=int(instruction["metadata_offset"])
                field_name=string.split(instruction["name"],';')[0]
                for field_tuple in protocols[protocol_name]:
                    if field_name==field_tuple[0]:
                        field_id=field_tuple[3]
                        break
                field_setting=core.PofManager.get_field(field_id)
                action=core.PofManager.new_action_set_field_from_metadata(field_setting, metadata_offset)
                action_list.append(action)
                
            if instruction['action_type']=="modify_field":
                print "instruction--apply-action--modify_field!"
                print instruction
                field_name=instruction["name"]
                for field_tuple in protocols[protocol_name]:
                    if field_name==field_tuple[0]:
                        field_id=field_tuple[3]
                        break
                match_field=core.PofManager.get_field(field_id)
                increment=int(instruction["Increment"])
                action=core.PofManager.new_action_modify_field(match_field, increment)
                action_list.append(action)
                
                
            if instruction['action_type']=="add_field":
                print "instruction--apply-action--add_field!"
                print instruction
                field_id=int(string.split(instruction["Existed_Field"],':')[0])
                field_position=int(instruction["field_offset"])
                field_length=int(instruction["field_length"])
                field_value=instruction["field_value"]
                action= core.PofManager.new_action_add_field(field_id, field_position, field_length, field_value)
                action_list.append(action)
                
            if instruction['action_type']=="delete_field":
                print "instruction--apply-action--delete_field!"
                print instruction
                field_position=int(instruction["offset"])
                if instruction["length_value_type"]=="VALUE":
                    length_value_type=0
                    length_value=int(instruction["length_value"])
                    length_field=None
                else:
                    length_value_type=1
                    length_value=0
                    length_field_id=int(string.split(instruction["length_field"],":")[0])
                    length_field=core.PofManager.get_field(length_field_id)
                action = core.PofManager.new_action_delete_field(field_position, length_value_type, length_value, length_field)
                action_list.append(action)
                
            if instruction['action_type']=="calculate_checksum":
                print "instruction--apply-action--calculate_checksum!"
                if instruction['checksum_pos_type']=="VALUE":
                    checksum_pos_type=0
                else:
                    checksum_pos_type=1
                if instruction['calc_pos_type']=="VALUE":
                    calc_pos_type=0
                else:
                    calc_pos_type=1                        
                checksum_position=int(instruction["Checksum_Position"])
                checksum_length=int(instruction["Checksum_Length"])
                calc_start_position=int(instruction["Calc_Start_Position"])
                calc_length=int(instruction["Calc_Length"])
                action=core.PofManager.new_action_calculate_checksum(checksum_pos_type,calc_pos_type,checksum_position,checksum_length,calc_start_position,calc_length)
                action_list.append(action)
                
            if instruction['action_type']=="group":
                print "instruction--apply-action--group!"
                group_id=instruction['Group_ID']
                group_id=0
                action=core.PofManager.new_action_group(group_id)
                action_list.append(action)
                
            if instruction['action_type']=="drop":
                print "instruction--apply-action--drop!"
                reason=of.ofp_drop_reason_rev_map[instruction['Reason']]
                action=core.PofManager.new_action_drop(reason)

            if instruction['action_type']=="packet_in":
                print "instruction--apply-action--packet_in!"
                if instruction['Reason']=="Entry_Reason_Code":
                    reason=int(instruction['other_reason'])
                else:
                    reason=of.ofp_packet_in_reason_rev_map[instruction['Reason']]
                action= core.PofManager.new_action_packetin(reason)
                action_list.append(action)
            if instruction['action_type']=="counter":
                print "instruction--apply-action--counter!"
                counter_id=instruction['Counter_ID']
                counter_id=0
                action=core.PofManager.new_action_counter(counter_id)
                action_list.append(action)
                       
        else:
            if action_list:
                ofinstruction=core.PofManager.new_ins_apply_actions(action_list)
                action_list=[]
            if instruction['action']=="goto_table":
                print "instruction--goto_table!"
                next_table_id=string.split(instruction['table_id'],':')[0]
                next_table_id=int(next_table_id)
                packet_offset=instruction['offset']
                packet_offset=int(packet_offset)
                switch_id=OnlyStr(Table["switch_id"])
                switch_id=int(switch_id,16)
                ofinstruction=core.PofManager.new_ins_goto_table(switch_id, next_table_id, packet_offset)
            if instruction['action']=="goto_direct_table":
                print "instruction--goto_direct_table!"
                next_table_id=string.split(instruction['table_id'],':')[0]
                next_table_id=int(next_table_id)
                Index_type=instruction["Index_Type"]
                if Index_type==0:   
                    Index_value=int(instruction["Index_value"])
                    Index_field=None
                else:
                    Index_value=0
                    Index_field_id=int(string.split(instruction["Index_field"],':')[0])
                    if Index_field_id==-1:
                        Index_field_name=string.split(instruction["Index_field"],':')[1]
                        Index_field=core.PofManager.get_metadata_field(Index_field_name)
                    else:
                        Index_field=core.PofManager.get_field(Index_field_id)
                packet_offset=int(instruction["offset"])
                ofinstruction=core.PofManager.new_ins_goto_direct_table(next_table_id, Index_type, packet_offset, Index_value,Index_field)
            if instruction['action']=="meter":
                print "instruction--meter"
                meter_id=int(instruction["Meter_ID"])
                ofinstruction=core.PofManager.new_ins_meter(meter_id)
            if instruction['action']=="write_metadata":
                print "instruction--write_metadata"
                metadata_name=string.split(instruction["metadata"],';')[0]
                metadata_field=core.PofManager.get_metadata_field(metadata_name)
                value=instruction["value"]
                ofinstruction=core.PofManager.new_ins_write_metadata(metadata_field.offset, metadata_field.length, value)
            if instruction['action']=="write_metadata_from_flow":
                print "instruction--write_metadata_from_flow"
                metadata_name=string.split(instruction["metadata"],';')[0]
                metadata_field=core.PofManager.get_metadata_field(metadata_name)
                packet_offset=int(instruction["Packet_Offset"])
                ofinstruction=core.PofManager.new_ins_write_metadata_from_packet(metadata_field.offset, metadata_field.length, packet_offset)
                
            if instruction['action']=="calculate_field":
                print "instruction--calculate_field"
                print instruction
                calc_type=of.ofp_calc_type_rev_map[instruction['calc_type']]
                if(instruction['src_type']=="VALUE"):
                    src_value_type=0
                    src_value=int(instruction['src_value'])
                    src_field=None
                else:
                    src_value_type=1
                    src_value=0
                    src_field_id=int(string.split(instruction["src_field"],':')[0])
                    if src_field_id==-1:
                        src_field_name=string.split(instruction["src_field"],':')[1]
                        src_field=core.PofManager.get_metadata_field(src_field_name)
                    else:
                        src_field=core.PofManager.get_field(src_field_id)
                if instruction['des_field']:
                    des_field_id=int(string.split(instruction["des_field"],':')[0])
                    if des_field_id==-1:
                        des_field_name=string.split(instruction["des_field"],':')[1]
                        des_field=core.PofManager.get_metadata_field(des_field_name)
                    else:
                        des_field=core.PofManager.get_field(des_field_id)
                else:
                    des_field=None    
                ofinstruction=core.PofManager.new_ins_calculate_field(calc_type, src_value_type, des_field, src_value, src_field)
                
            if instruction['action']=="move_packet_offset":
                print "instruction--move_packet_offset"
                print instruction
                
            
        if ofinstruction:
            print ofinstruction
            ofinstructions.append(ofinstruction)
    if action_list:
        ofinstruction=core.PofManager.new_ins_apply_actions(action_list)
        action_list=[]
        ofinstructions.append(ofinstruction)
    if len(ofinstructions)<=6:
        switch_id=Table_entry['switch_id']
        switch_id=OnlyStr(switch_id)
        switch_id=int(switch_id,16)
        flow_entry_id=core.PofManager.add_flow_entry(switch_id,Table_entry['table_global_id'],matchx_list,ofinstructions,Table_entry['priority'],Table_entry['counter_enable'])   
        return 0,flow_entry_id
    else:
        ofinstructions=[]
        return 1,0
def launch ():
    core.registerNew(POFdesk)