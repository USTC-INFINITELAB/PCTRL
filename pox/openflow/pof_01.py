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
In charge of POF switches.

NOTE: This module is loaded automatically on startup unless POX is run
      with --no-openflow .
"""
from pox.core import core
import pox
import pox.lib.util
from pox.lib.addresses import EthAddr
from pox.lib.revent.revent import EventMixin
import datetime
import time
from pox.lib.socketcapture import CaptureSocket
import pox.openflow.debug
from pox.openflow.util import make_type_to_unpacker_table
from pox.openflow import *
import pox.openflow.bypassmanager as bpm   # edit by cc

log = core.getLogger()

import socket
import select

# List where the index is an OpenFlow message type (OFPT_xxx), and
# the values are unpack functions that unpack the wire format of that
# type into a message object.
unpackers = make_type_to_unpacker_table()

try:
    PIPE_BUF = select.PIPE_BUF
except:
    try:
        # Try to get it from where PyPy (sometimes) has it
        import IN
        PIPE_BUF = IN.PIPE_BUF
    except:
        # (Hopefully) reasonable default
        PIPE_BUF = 512

#import pox.openflow.libopenflow_01 as of
#import pox.openflow.libpof_01 as of
import pox.openflow.libpof_02 as of
#import pox.openflow.libpof_01_tianye as of

import threading
import os
import sys
import exceptions
from errno import EAGAIN, ECONNRESET, EADDRINUSE, EADDRNOTAVAIL


import traceback


def handle_HELLO (con, msg): #S
    #con.msg("HELLO wire protocol " + hex(msg.version))
    #print "CC: receive HELLO message\n",msg
    
    # Send a features request
    msg = of.ofp_features_request()
    con.send(msg)
    #print ("send Features_Request message")

def handle_ECHO_REPLY (con, msg):
    #con.msg("Got echo reply")
    pass

def handle_ECHO_REQUEST (con, msg): #S
    reply = msg
    reply.header_type = of.OFPT_ECHO_REPLY
    con.send(reply)

def handle_FLOW_REMOVED (con, msg): #A
    e = con.ofnexus.raiseEventNoErrors(FlowRemoved, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(FlowRemoved, con, msg)
"""
def handle_FEATURES_REPLY (con, msg):
    #print(msg)
    #print ("receive Features_Reply message")   #print information
    connecting = con.connect_time == None       #connect_time = None as default, so connecting = ture
    print ("con.connect_time:",con.connect_time)
    con.features = msg
    #con.original_ports._ports = set(msg.ports)
    #con.ports._reset()
    #con.dpid = msg.datapath_id
    con.dpid = msg.dev_id

    if not connecting:
        con.ofnexus._connect(con)
        e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
        if e is None or e.halt != True:
            con.raiseEventNoErrors(FeaturesReceived, con, msg)
        return

    #OpenFlowConnectionArbiter is defined and registered in openflow.__init__.py
    nexus = core.OpenFlowConnectionArbiter.getNexus(con)    # nexus = core.openflow (class OpenFlowNexus)
    print ('fun handle_FEATURES_REPLY --> nexus', nexus)    # cc
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
            con.info("connected")
            con.connect_time = time.time()
            e = con.ofnexus.raiseEventNoErrors(ConnectionUp, con, msg)
            if e is None or e.halt != True:
                con.raiseEventNoErrors(ConnectionUp, con, msg)
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
        con.send(of.ofp_set_config(miss_send_len = 0xffff))   # cc
    

    '''
    if con.ofnexus.clear_flows_on_connect:
        con.send(of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE))
    '''
    
    con.send(getGonfigReq)
    
    '''
    # Hack for old versions of cbench
    class C (object):
        xid = barrier.xid
    finish_connecting(C())
    '''
"""
def handle_STATS_REPLY (con, msg):
    e = con.ofnexus.raiseEventNoErrors(RawStatsReply, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(RawStatsReply, con, msg)
    con._incoming_stats_reply(msg)
"""
def handle_PORT_STATUS (con, msg): #A
    #print(msg)
    if msg.reason == of.OFPPR_DELETE:
        con.ports._forget(msg.desc)
    else:
        con.ports._update(msg.desc)
    e = con.ofnexus.raiseEventNoErrors(PortStatus, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(PortStatus, con, msg)
"""
def handle_PACKET_IN (con, msg): #A
    e = con.ofnexus.raiseEventNoErrors(PacketIn, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(PacketIn, con, msg)

def handle_ERROR_MSG (con, msg): #A
    err = ErrorIn(con, msg)
    e = con.ofnexus.raiseEventNoErrors(err)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(err)
    if err.should_log:
        log.error(str(con) + " OpenFlow Error:\n" +
              msg.show(str(con) + " Error: ").strip())

def handle_BARRIER (con, msg):
    #print("receive barrier reply message")   #print information
    e = con.ofnexus.raiseEventNoErrors(BarrierIn, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(BarrierIn, con, msg)

# handlers for stats replies
def handle_OFPST_DESC (con, parts):
    msg = parts[0].body
    e = con.ofnexus.raiseEventNoErrors(SwitchDescReceived,con,parts[0],msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(SwitchDescReceived, con, parts[0], msg)

def handle_OFPST_FLOW (con, parts):
    msg = []
    for part in parts:
        msg.extend(part.body)
    e = con.ofnexus.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(FlowStatsReceived, con, parts, msg)

def handle_OFPST_AGGREGATE (con, parts):
    msg = parts[0].body
    e = con.ofnexus.raiseEventNoErrors(AggregateFlowStatsReceived, con,
                                     parts[0], msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(AggregateFlowStatsReceived, con, parts[0], msg)

def handle_OFPST_TABLE (con, parts):
    msg = []
    for part in parts:
        msg.extend(part.body)
    e = con.ofnexus.raiseEventNoErrors(TableStatsReceived, con, parts, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(TableStatsReceived, con, parts, msg)

def handle_OFPST_PORT (con, parts):
    msg = []
    for part in parts:
        msg.extend(part.body)
    e = con.ofnexus.raiseEventNoErrors(PortStatsReceived, con, parts, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(PortStatsReceived, con, parts, msg)

def handle_OFPST_QUEUE (con, parts):
    msg = []
    for part in parts:
        msg.extend(part.body)
    e = con.ofnexus.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(QueueStatsReceived, con, parts, msg)

def handle_VENDOR (con, msg):   # FIXME: need to change to experiment
    log.info("Vendor msg: " + str(msg))
    
def handle_GET_CONFIG_REPLY (con, msg):
    #print "CC: receive GET_CONFIG_REPLY message\n",msg  #cc
    e = con.ofnexus.raiseEventNoErrors(GetConfigReply, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(GetConfigReply, con, msg)
"""        
def handle_RESOURCE_REPORT (con, msg):
    #print ("receive Resource_report message")  #cc
    #print msg                                 # cc: for test
    e = con.ofnexus.raiseEventNoErrors(ResourceReport, con, msg)
    if e is None or e.halt != True:
        con.raiseEventNoErrors(ResourceReport, con, msg)
    pass
"""
    
# A list, where the index is an OFPT, and the value is a function to
# call for that type
# This is generated automatically based on handlerMap
handlers = []

# Message handlers
handlerMap = {
  of.OFPT_HELLO : handle_HELLO,                           # 0
  of.OFPT_ERROR : bpm.handle_ERROR_MSG,                   # 1   handled by bypassmanager
  of.OFPT_ECHO_REQUEST : handle_ECHO_REQUEST,             # 2
  of.OFPT_ECHO_REPLY : handle_ECHO_REPLY,                 # 3
  of.OFPT_EXPERIMENTER : handle_VENDOR,                   # FIXME: 4
  of.OFPT_FEATURES_REPLY : bpm.handle_FEATURES_REPLY,     # 6   handled by bypassmanager
  of.OFPT_GET_CONFIG_REPLY: handle_GET_CONFIG_REPLY,      # 8
  of.OFPT_PACKET_IN : bpm.handle_PACKET_IN,               # 10  handled by bypassmanager
  of.OFPT_FLOW_REMOVED : handle_FLOW_REMOVED,             # 11
  of.OFPT_PORT_STATUS : bpm.handle_PORT_STATUS,           # 12  handled by bypassmanager
  of.OFPT_RESOURCE_REPORT: bpm.handle_RESOURCE_REPORT,    # 13  handled by bypassmanager
  of.OFPT_BARRIER_REPLY : handle_BARRIER,                 # 22
  of.OFPT_MULTIPART_REPLY : handle_STATS_REPLY,           # FIXME:20 
  of.OFPT_COUNTER_REPLY: bpm.handle_COUNTER_REPLY,        # 33  handled by bypassmanager
}
"""
statsHandlerMap = {
  of.OFPST_DESC : handle_OFPST_DESC,
  of.OFPST_FLOW : handle_OFPST_FLOW,
  of.OFPST_AGGREGATE : handle_OFPST_AGGREGATE,
  of.OFPST_TABLE : handle_OFPST_TABLE,
  of.OFPST_PORT : handle_OFPST_PORT,
  of.OFPST_QUEUE : handle_OFPST_QUEUE,
}
"""

class DeferredSender (threading.Thread):
    """
    Class that handles sending when a socket write didn't complete
    Deferred sending should be unusual, so don't worry too much about efficiency
    """
    def __init__ (self):
        threading.Thread.__init__(self)
        core.addListeners(self)
        self._dataForConnection = {}
        self._lock = threading.RLock()
        self._waker = pox.lib.util.makePinger()
        self.sending = False
    
        self.start()

    def _handle_GoingDownEvent (self, event):
        self._waker.ping()

    def _sliceup (self, data):
        """
        Takes an array of data bytes, and slices into elements of
        PIPE_BUF bytes each
        """
        out = []
        while len(data) > PIPE_BUF:
            out.append(data[0:PIPE_BUF])
            data = data[PIPE_BUF:]
        if len(data) > 0:
            out.append(data)
        return out

    def send (self, con, data):
        with self._lock:
            self.sending = True
    
            data = self._sliceup(data)
    
            if con not in self._dataForConnection:
                self._dataForConnection[con] = data
            else:
                self._dataForConnection[con].extend(data)
    
            self._waker.ping()

    def kill (self, con):
        with self._lock:
            try:
                del self._dataForConnection[con]
            except:
                pass
    
            self._waker.ping()

    def run (self):
        while core.running:
            #print ('DeferredSender running...','thread_count:',threading.active_count()) # cc:
    
            with self._lock:
                cons = self._dataForConnection.keys()
    
            rlist, wlist, elist = select.select([self._waker], cons, cons, 5)
            if not core.running: break
    
            with self._lock:
                if len(rlist) > 0:
                    self._waker.pongAll()
        
                for con in elist:
                    try:
                        del self._dataForConnection[con]
                    except:
                        pass
        
                for con in wlist:
                    try:
                        alldata = self._dataForConnection[con]
                        while len(alldata):
                            data = alldata[0]
                            try:
                                l = con.sock.send(data)
                                if l != len(data):
                                    alldata[0] = data[l:]
                                    break
                                del alldata[0]
                            except socket.error as (errno, strerror):
                                if errno != EAGAIN:
                                    con.msg("DeferredSender/Socket error: " + strerror)
                                    log.error("pof_01.DeferredSender.run --- disconnect")  #CC
                                    con.disconnect()
                                    del self._dataForConnection[con]
                                break
                            except:
                                con.msg("Unknown error doing deferred sending")
                                break
                        if len(alldata) == 0:
                            try:
                                del self._dataForConnection[con]
                                if len(self._dataForConnection) == 0:
                                    self.sending = False
                                    break
                            except:
                                pass
                    except:
                        try:
                            del self._dataForConnection[con]
                        except:
                            pass

class DummyOFNexus (object):
    def raiseEventNoErrors (self, event, *args, **kw):
        log.warning("%s raised on dummy OpenFlow nexus" % event)
    def raiseEvent (self, event, *args, **kw):
        log.warning("%s raised on dummy OpenFlow nexus" % event)
    def _disconnect (self, dpid):
        log.warning("%s disconnected on dummy OpenFlow nexus", pox.lib.util.dpidToStr(dpid))

_dummyOFNexus = DummyOFNexus()


"""
class FileCloser (object):
  def __init__ (self):
    from weakref import WeakSet
    self.items = WeakSet()
    core.addListeners(self)
    import atexit
    atexit.register(self._handle_DownEvent, None)

  def _handle_DownEvent (self, event):
    for item in self.items:
      try:
        item.close()
      except Exception:
        log.exception("Couldn't close a file while shutting down")
    self.items.clear()

_itemcloser = FileCloser()
"""


class OFCaptureSocket (CaptureSocket):
    """
    Captures OpenFlow data to a pcap file
    """
    def __init__ (self, *args, **kw):
        super(OFCaptureSocket,self).__init__(*args, **kw)
        self._rbuf = bytes()
        self._sbuf = bytes()
        self._enabled = True
        #_itemcloser.items.add(self)

    def _recv_out (self, buf):
        if not self._enabled: return
        self._rbuf += buf
        l = len(self._rbuf)
        while l > 4:
            if ord(self._rbuf[0]) != of.OFP_VERSION:
                log.error("Bad OpenFlow version while trying to capture trace")
                self._enabled = False
                break
            packet_length = ord(self._rbuf[2]) << 8 | ord(self._rbuf[3])
            if packet_length > l: break
            try:
                self._writer.write(False, self._rbuf[:packet_length])
            except Exception:
                log.exception("Exception while writing controller trace")
                self._enabled = False
            self._rbuf = self._rbuf[packet_length:]
            l = len(self._rbuf)

    def _send_out (self, buf, r):
        if not self._enabled: return
        self._sbuf += buf
        l = len(self._sbuf)
        while l > 4:
            if ord(self._sbuf[0]) != of.OFP_VERSION:
                log.error("Bad OpenFlow version while trying to capture trace")
                self._enabled = False
                break
            packet_length = ord(self._sbuf[2]) << 8 | ord(self._sbuf[3])
            if packet_length > l: break
            try:
                self._writer.write(True, self._sbuf[:packet_length])
            except Exception:
                log.exception("Exception while writing controller trace")
                self._enabled = False
            self._sbuf = self._sbuf[packet_length:]
            l = len(self._sbuf)


class PortCollection (object):
    """
    Keeps track of lists of ports and provides nice indexing.

    NOTE: It's possible this could be simpler by inheriting from UserDict,
            but I couldn't swear without looking at UserDict in some detail,
            so I just implemented a lot of stuff by hand.
    """
    def __init__ (self):
        self._ports = set()
        self._masks = set()
        self._chain = None

    def _reset (self):
        self._ports.clear()
        self._masks.clear()

    def _forget (self, port_id):
        self._masks.add(port_id)
        self._ports = set([p for p in self._ports if p.port_id != port_id])

    def _update (self, port):
        self._masks.discard(port.port_id)
        self._ports = set([p for p in self._ports if p.port_id != port.port_id])
        self._ports.add(port)

    def __str__ (self):
        if len(self) == 0:
            return "<Ports: Empty>"
        l = ["%s:%i"%(p.name,p.port_id) for p in sorted(self.values())]
        return "<Ports: %s>" % (", ".join(l),)

    def __len__ (self):
        return len(self.keys())

    def __getitem__ (self, index):
        if isinstance(index, (int,long)):
            for p in self._ports:
                if p.port_id == index:
                    return p
        elif isinstance(index, EthAddr):
            for p in self._ports:
                if p.hw_addr == index:
                    return p
        else:
            for p in self._ports:
                if p.name == index:
                    return p
        if self._chain:
            p = self._chain[index]
            if p.port_id not in self._masks:
                return p
    
        raise IndexError("No key %s" % (index,))

    def keys (self):
        if self._chain:
            k = set(self._chain.keys())
            k.difference_update(self._masks)
        else:
            k = set()
        k.update([p.port_id for p in self._ports])
        return list(k)

    def __iter__ (self):
        return iter(self.keys())

    def iterkeys (self):
        return iter(self.keys())

    def __contains__ (self, index):
        try:
            self[index]
            return True
        except Exception:
            pass
        return False

    def values (self):
        return [self[k] for k in self.keys()]

    def items (self):
        return [(k,self[k]) for k in self.keys()]
    """
    def iterkeys (self):
        return iter(self.keys())
    """
    def itervalues (self):
        return iter(self.values())
    def iteritems (self):
        return iter(self.items())
    def has_key (self, k):
        return k in self
    def get (self, k, default=None):
        try:
            return self[k]
        except IndexError:
            return default
    def copy (self):
        r = PortCollection()
        r._ports = set(self.values())


class Connection (EventMixin):
    """
      A Connection object represents a single TCP session with an
      openflow-enabled switch.
      If the switch reconnects, a new connection object is instantiated.
    """
    _eventMixin_events = set([
        ConnectionUp,
        ConnectionDown,
        PortStatus,
        FlowRemoved,
        PacketIn,
        ErrorIn,
        BarrierIn,
        RawStatsReply,
        SwitchDescReceived,
        FlowStatsReceived,
        AggregateFlowStatsReceived,
        TableStatsReceived,
        PortStatsReceived,
        QueueStatsReceived,
        FlowRemoved,
        GetConfigReply,   #cc
        ResourceReport,
    ])

    # Globally unique identifier for the Connection instance
    ID = 0

    def msg (self, m):
        #print str(self), m
        log.debug(str(self) + " " + str(m))
    def err (self, m):
        #print str(self), m
        log.error(str(self) + " " + str(m))
    def info (self, m):
        pass
        #print str(self), m
        log.info(str(self) + " " + str(m))

    def __init__ (self, sock):
        self._previous_stats = []
    
        self.ofnexus = _dummyOFNexus
        self.sock = sock
        self.buf = ''
        Connection.ID += 1
        self.ID = Connection.ID
        # TODO: dpid and features don't belong here; they should be eventually
        # be in topology.switch
        self.dpid = None
        self.features = None
        self.disconnected = False
        self.disconnection_raised = False
        self.connect_time = None
        self.idle_time = time.time()
    
        self.send(of.ofp_hello())
    
        self.original_ports = PortCollection()
        self.ports = PortCollection()
        self.ports._chain = self.original_ports
    
        #TODO: set a time that makes sure we actually establish a connection by
        #      some timeout

    @property
    def eth_addr (self):
        dpid = self.dpid
        if self.dpid is None:
            raise RuntimeError("eth_addr not available")
        return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

    def fileno (self):
        return self.sock.fileno()

    def close (self):
        log.info("pof_01.Connection.close() --- disconnected")  #CC
        self.disconnect('closed')
        try:
            self.sock.close()
        except:
            pass

    def disconnect (self, msg = 'disconnected', defer_event = False):
        """
        disconnect this Connection (usually not invoked manually).
        """
        if self.disconnected:
            self.msg("already disconnected")
        self.info(msg)
        self.disconnected = True
        try:
            #print '1111111111111'  #CC
            self.ofnexus._disconnect(self.dpid)
        except:
            pass
        if self.dpid is not None:
            #print '2222222222222'  #CC
            if not self.disconnection_raised and not defer_event:
                self.disconnection_raised = True
                self.ofnexus.raiseEventNoErrors(ConnectionDown, self)
                self.raiseEventNoErrors(ConnectionDown, self)
    
        try:
            #deferredSender.kill(self)
            pass
        except:
            pass
        try:
            #print '33333333333333'  #CC
            self.sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            pass
            #TODO disconnect notification
        except:
            pass

    def send (self, data):
        """
        Send data to the switch.
    
        Data should probably either be raw bytes in OpenFlow wire format, or
        an OpenFlow controller-to-switch message object from libopenflow.
        """
        if self.disconnected: return
        if type(data) is not bytes:
            # There's actually no reason the data has to be an instance of
            # ofp_header, but this check is likely to catch a lot of bugs,
            # so we check it anyway.
            assert isinstance(data, of.ofp_header)
            #self.info("[Send] POF message "+"[length] "+str(len(data))+" [type] "+str(data.header_type) + ", " + 
            #          of.ofp_type_map[data.header_type])     #add by CC
            #print of.ofp_type_map[data.header_type]   #CC
            data = data.pack()
        
        if deferredSender.sending:
            log.debug("deferred sender is sending!")
            deferredSender.send(self, data)
            return
        try:
            l = self.sock.send(data)
            if l != len(data):
                self.msg("Didn't send complete buffer.")
                data = data[l:]
                deferredSender.send(self, data)
        except socket.error as (errno, strerror):
            if errno == EAGAIN:   # EAGIAN = 11
                self.msg("Out of send buffer space.  " +
                         "Consider increasing SO_SNDBUF.")
                deferredSender.send(self, data)
            ############ add by CC ##############
            elif errno == 10035:
                log.info("error " + str(errno))   #CC
                   
                time.sleep(0.1)
                l = self.sock.send(data)
                if l != len(data):
                    self.msg("Didn't send complete buffer.")
                    data = data[l:]
                    deferredSender.send(self, data)
                
                #deferredSender.send(self, data)
            ############ add by CC ##############
            else:
                self.msg("Socket error: " + strerror)
                log.info("pof_01.Connection.send --- disconnected")  #CC
                print('errno', errno)   #CC
                self.disconnect(defer_event=True)

    def read (self):
        """
        Read data from this connection.  Generally this is just called by the
        main OpenFlow loop below.
    
        Note: This function will block if data is not available.
        """
        try:
            d = self.sock.recv(2048)
        except:
            return False
        if len(d) == 0:
            #print('len(d) == 0')  #cc
            return False
        self.buf += d
        buf_len = len(self.buf)
    
    
        offset = 0
        while buf_len - offset >= 8: # 8 bytes is minimum OF message size
            # We pull the first four bytes of the OpenFlow header off by hand
            # (using ord) to find the version/length/type so that we can
            # correctly call libpof to unpack it.
    
            ofp_type = ord(self.buf[offset+1])
    
            #if ord(self.buf[offset]) != of.OFP_VERSION:
            if ord(self.buf[offset]) != 4:
                if ofp_type == of.OFPT_HELLO:
                    # We let this through and hope the other side switches down.
                    pass
                else:
                    log.warning("Bad OpenFlow version (0x%02x) on connection %s"
                              % (ord(self.buf[offset]), self))
                    return False # Throw connection away
            else:
                #print "pof_01 --> POF messages type:", ofp_type,",", pofMsgMap[ofp_type],   #cc
                pass
                
    
            msg_length = ord(self.buf[offset+2]) << 8 | ord(self.buf[offset+3])
            #print ", message length:",msg_length
            #self.info("[Recv] POF message " + "[length] " + str(msg_length) + " [type] " + str(ofp_type) + ", " + 
            #          of.ofp_type_map[ofp_type])
    
            if buf_len - offset < msg_length: break
    
            new_offset,msg = unpackers[ofp_type](self.buf, offset)
            assert new_offset - offset == msg_length
            offset = new_offset
            
            log.debug(str(msg))
    
            try:
                h = handlers[ofp_type]
                h(self, msg)
            except:
                log.exception("%s: Exception while handling OpenFlow message:\n" +
                          "%s %s", self,self,
                          ("\n" + str(self) + " ").join(str(msg).split('\n')))
                continue
    
        if offset != 0:
            self.buf = self.buf[offset:]
    
        return True

    def _incoming_stats_reply (self, ofp):
        # This assumes that you don't receive multiple stats replies
        # to different requests out of order/interspersed.
        if not ofp.is_last_reply:
            if ofp.type not in [of.OFPST_FLOW, of.OFPST_TABLE,
                                    of.OFPST_PORT, of.OFPST_QUEUE]:
                log.error("Don't know how to aggregate stats message of type " +
                      str(ofp.type))
                self._previous_stats = []
                return
    
        if len(self._previous_stats) != 0:
            if ((ofp.xid == self._previous_stats[0].xid) and
              (ofp.type == self._previous_stats[0].type)):
                self._previous_stats.append(ofp)
            else:
                log.error("Was expecting continued stats of type %i with xid %i, " +
                      "but got type %i with xid %i" %
                      (self._previous_stats_reply.xid,
                        self._previous_stats_reply.type,
                        ofp.xid, ofp.type))
                self._previous_stats = [ofp]
        else:
            self._previous_stats = [ofp]
    
        if ofp.is_last_reply:
            handler = statsHandlerMap.get(self._previous_stats[0].type, None)
            s = self._previous_stats
            self._previous_stats = []
            if handler is None:
                log.warn("No handler for stats of type " +
                         str(self._previous_stats[0].type))
                return
            handler(self, s)

    def __str__ (self):
        #return "[Con " + str(self.ID) + "/" + str(self.dpid) + "]"
        if self.dpid is None:
            d = str(self.dpid)
        else:
            d = pox.lib.util.dpidToStr(self.dpid)
        return "[%s %i]" % (d, self.ID)


def wrap_socket (new_sock):
    fname = datetime.datetime.now().strftime("%Y-%m-%d-%I%M%p")
    fname += "_" + new_sock.getpeername()[0].replace(".", "_")
    fname += "_" + `new_sock.getpeername()[1]` + ".pcap"
    pcapfile = file(fname, "w")
    try:
        new_sock = OFCaptureSocket(new_sock, pcapfile, local_addrs=(None,None,6633))
    except Exception:
        #import traceback
        traceback.print_exc()
        pass
    return new_sock


#from pox.lib.recoco.recoco import *
from pox.lib.recoco.recoco import Task
from pox.lib.recoco.recoco import Select

class POF_01_Task (Task):
    """
    The main recoco thread for listening to openflow messages
    """
    def __init__ (self, port = 6633, address = '0.0.0.0'):
        Task.__init__(self)
        self.port = int(port)
        self.address = address
        self.started = False
    
        core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)

    def _handle_GoingUpEvent (self, event):
        self.start()

    def start (self):
        if self.started:
            return
        self.started = True
        #print('POF_01_Task --> start()')
        return super(POF_01_Task,self).start()

    def run (self):
        # List of open sockets/connections to select on
        sockets = []
    
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.address, self.port))
        except socket.error as (errno, strerror):
            log.error("Error %i while binding socket: %s", errno, strerror)
            if errno == EADDRNOTAVAIL:
                log.error(" You may be specifying a local address which is "
                      "not assigned to any interface.")
            elif errno == EADDRINUSE:
                log.error(" You may have another controller running.")
                log.error(" Use openflow.of_01 --port=<port> to run POX on "
                      "another port.")
            return
    
        listener.listen(16)
        sockets.append(listener)
    
        log.debug("Listening on %s:%s" % (self.address, self.port))
    
        con = None
        while core.running:
            try:
                while True:
                    #print ('of_01 running...','thread_count:',threading.active_count()) #print information
                    con = None
                    rlist, wlist, elist = yield Select(sockets, [], sockets, 5)
                    if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
                        if not core.running: break
        
                    for con in elist:
                        if con is listener:
                            raise RuntimeError("Error on listener socket")
                        else:
                            try:
                                con.close()
                            except:
                                pass
                            try:
                                sockets.remove(con)
                            except:
                                pass
        
                    timestamp = time.time()
                    for con in rlist:
                        #print ('len(rlist)',len(rlist))
                        if con is listener:                       # ovs connected
                            new_sock = listener.accept()[0]
                            if pox.openflow.debug.pcap_traces:
                                new_sock = wrap_socket(new_sock)
                            new_sock.setblocking(1)     #changed by CC, changed to blocked
                            # Note that instantiating a Connection object fires a
                            # ConnectionUp event (after negotation has completed)
                            newcon = Connection(new_sock)        # generate a new instance of class 'Connection'
                            sockets.append( newcon )
                            #print str(newcon) + " connected"
                        else:
                            con.idle_time = timestamp
                            if con.read() is False:    # do the read function of class 'Connection'
                                print('con.read() is False')
                                con.close()
                                sockets.remove(con)
            except exceptions.KeyboardInterrupt:
                break
            except:
                doTraceback = True
                if sys.exc_info()[0] is socket.error:
                    if sys.exc_info()[1][0] == ECONNRESET:
                        con.info("Connection reset")
                        doTraceback = False
        
                if doTraceback:
                    log.exception("Exception reading connection " + str(con))
        
                if con is listener:
                    log.error("Exception on OpenFlow listener.  Aborting.")
                    break
                try:
                    con.close()
                except:
                    pass
                try:
                    sockets.remove(con)
                except:
                    pass
    
        log.debug("No longer listening for connections")
    
        #pox.core.quit()


def _set_handlers ():
    handlers.extend([None] * (1 + sorted(handlerMap.keys(),reverse=True)[0]))
    for h in handlerMap:
        handlers[h] = handlerMap[h]
        #print handlerMap[h]
    
_set_handlers()


# Used by the Connection class
deferredSender = None

def launch (port = 6633, address = "0.0.0.0"):
    if core.hasComponent('pof_01'):
        return None

    global deferredSender
    deferredSender = DeferredSender()   # run the __init__ function and start function
    
    if of._logger is None:
        #of._logger = core.getLogger('libopenflow_01')
        of._logger = core.getLogger('libpof_02')
    
    l = POF_01_Task(port = int(port), address = address)   # an instance of class 'POF_01_Task'
    core.register("pof_01", l)
    #print('of_01 has been launched')   #print information
    return l