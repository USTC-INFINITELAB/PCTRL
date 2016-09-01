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

ByPassManager Module
process 6 pof messages:
    FEATURES_REPLY
    PORT_STATUS
    RESOURCE_REPORT
    COUNTER_REPLY
    ERROR
    PACKETIN
'''

import time
import threading

#import pox.openflow.libpof_01 as of
import pox.openflow.libpof_02 as of
#import pox.openflow.libpof_01_tianye as of
import pox.lib.util
from pox.openflow import FeaturesReceived
from pox.openflow import ConnectionUp
from pox.openflow import PortStatus
from pox.openflow import GetConfigReply
from pox.openflow import ResourceReport
from pox.openflow import ErrorIn
from pox.openflow import PacketIn

from pox.core import core

log = core.getLogger()

def echo_cycle(con):
    def sayhello():
        #print "send echo_request"
        con.send(of.ofp_echo_request())
        global t
        t = threading.Timer(2.0, sayhello)
        t.start()
    t = threading.Timer(2.0, sayhello)
    t.start()

def handle_FEATURES_REPLY (con, msg):    #type:6
    #print "CC: receive Features_Reply message\n",msg
    connecting = con.connect_time == None       #connect_time = None as default, so connecting = ture
    #print ("con.connect_time:",con.connect_time)
    con.features = msg
    con.dpid = msg.device_id
    con.port_num_received = 0

    if not connecting:
        con.ofnexus._connect(con)
        e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
        if e is None or e.halt != True:
            con.raiseEventNoErrors(FeaturesReceived, con, msg)
        return

    #OpenFlowConnectionArbiter is defined and registered in openflow.__init__.py
    nexus = core.OpenFlowConnectionArbiter.getNexus(con)    # nexus = core.openflow (class OpenFlowNexus)
    #print ('fun handle_FEATURES_REPLY --> nexus', nexus)    # cc
    if nexus is None:
        # Cancel connection
        con.info("No OpenFlow nexus for " + pox.lib.util.dpidToStr(msg.dev_id))
        con.disconnect()
        return
    con.ofnexus = nexus
    con.ofnexus._connect(con)    # self._connections[con.dpid] = con (in class OpenFlowNexus)
    #connections[con.dpid] = con

    #barrier = of.ofp_barrier_request()
    getGonfigReq = of.ofp_get_config_request()

    listeners = []

    def finish_connecting (event):
        if event.xid != getGonfigReq.xid:
            con.dpid = None
            con.err("failed connect")
            con.disconnect()
        else:
            """
            con.info("connected")
            con.connect_time = time.time()
            e = con.ofnexus.raiseEventNoErrors(ConnectionUp, con, msg)
            if e is None or e.halt != True:
                con.raiseEventNoErrors(ConnectionUp, con, msg)
            """
            e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
            if e is None or e.halt != True:
                con.raiseEventNoErrors(FeaturesReceived, con, msg)
        con.removeListeners(listeners)
    listeners.append(con.addListener(GetConfigReply, finish_connecting))
    
    def also_finish_connecting (event):
        if event.xid != getGonfigReq.xid: return
        if event.ofp.type != of.OFPET_BAD_REQUEST: return
        if event.ofp.code != of.OFPBRC_BAD_TYPE: return
        # Okay, so this is probably an HP switch that doesn't support barriers
        # (ugh).  We'll just assume that things are okay.
        finish_connecting(event)
    listeners.append(con.addListener(ErrorIn, also_finish_connecting))

    #TODO: Add a timeout for finish_connecting
    
    #print ('con.ofnexus.miss_send_len',con.ofnexus.miss_send_len)  #cc
    if con.ofnexus.miss_send_len is not None:
        #con.send(of.ofp_set_config(miss_send_len = con.ofnexus.miss_send_len))
        con.send(of.ofp_set_config(miss_send_len = 0xffff))

    con.send(getGonfigReq)

def handle_PORT_STATUS (con, msg):    # type:12
    #print "CC: receive PORT_STATUS message\n",msg
    if msg.reason == of.OFPPR_DELETE:
        con.ports._forget(msg.desc)
    else:
        con.ports._update(msg.desc)
    e = con.ofnexus.raiseEventNoErrors(PortStatus, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(PortStatus, con, msg)
    con.port_num_received += 1
    if con.port_num_received == con.features.port_num:
        con.info("connected")
        con.connect_time = time.time()
        e = con.ofnexus.raiseEventNoErrors(ConnectionUp, con, msg)
        if e is None or e.halt != True:
            con.raiseEventNoErrors(ConnectionUp, con, msg)

def handle_RESOURCE_REPORT (con, msg):      # type:13
    #print "CC: receive RESOURCE_REPORT message\n",msg
    e = con.ofnexus.raiseEventNoErrors(ResourceReport, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(ResourceReport, con, msg)
    echo_cycle(con)

def handle_PACKET_IN (con, msg):   # type: 10
    #print "CC: receive PACKET_IN message\n", msg
    e = con.ofnexus.raiseEventNoErrors(PacketIn, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(PacketIn, con, msg)
        
def handle_ERROR_MSG (con, msg):   # type: 1
    #print "CC: receive RESOURCE_REPORT message\n",msg
    err = ErrorIn(con, msg)
    e = con.ofnexus.raiseEventNoErrors(err)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(err)
    if err.should_log:
        log.error(str(con) + " OpenFlow Error:\n" +
              msg.show(str(con) + " Error: ").strip())

def handle_COUNTER_REPLY (con, msg):
    print "CC: receive COUNTER_REPLY message\n",msg

