from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet.ether_types import ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_LLDP

class LoadBalancer(app_manager.RyuApp):
  # declare what version of the open-flow adapted in this application
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  VIRTUAL_IP = '10.0.0.100'

  def __init__(self, *args, **kwargs):
    super(LoadBalancer, self).__init__(*args, **kwargs)
    # pre-configure information about all servers
    self.configured_servers = [{
      'ip': '10.0.0.1',
      'mac': '00:00:00:00:00:01',
      'port': 1
    }, {
      'ip': '10.0.0.2',
      'mac': '00:00:00:00:00:02',
      'port': 2
    }, {
      'ip': '10.0.0.3',
      'mac': '00:00:00:00:00:03',
      'port': 3
    }]
    # the map to map the mac table of different switch
    # here only implement one mac table for one switch
    self.mac_to_port = {}

    # the record for roubd robin implementation
    self.current_server = self.configured_servers[0]
    self.current_index = 0

  def add_default_table(self, datapath):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionGotoTable(self.FILTER_TABLE)]
    mod = parser.OFPFlowMod(datapath=datapath, table_id=0, instructions=inst)
    datapath.send_msg(mod)

  # the function is called when controller is just started,
  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def switch_features_handler(self, event):
    datapath = event.msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    # config the table-miss flow entry for controller controll the traffic
    # in the network 
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    self.add_flow(datapath, 0, match, actions)

  # the function to add the flow entry into the controller
  def add_flow(self, datapath, priority, match, actions, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    if buffer_id:
      mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
    else:
      mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
    datapath.send_msg(mod)


  # the function is called when a packet arrives from the swtich
  # and switch has no clues what to do with packet
  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def packet_in_handler(self, event):

    if (event.msg.msg_len < event.msg.total_len):
      self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

    # read the packet content
    msg = event.msg
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    in_port = msg.match['in_port'] # the port that client send to the switch
    dpid = datapath.id


    # wrap up the message to ethernet frame
    pkt = packet.Packet(msg.data)
    ethernetFrame = pkt.get_protocol(ethernet.ethernet)

    # drop all LLDP protocol packets
    if (ethernetFrame.ethertype == ETH_TYPE_LLDP):
      return

    self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

    # read the mac address from ethernet frame
    dst_mac = ethernetFrame.dst
    src_mac = ethernetFrame.src

    # record the relationship between mac and port
    self.mac_to_port.setdefault(dpid, {})
    self.mac_to_port[dpid][src_mac] = in_port


    # if the dst_mac exist in the mac_to_port map, then
    # it represents that controller must have learned the flow entry
    if (dst_mac in self.mac_to_port[dpid]):
      out_port = self.mac_to_port[dpid][dst_mac]
    else:
      out_port = ofproto.OFPP_FLOOD

    actions = [parser.OFPActionOutput(out_port)]

    # if controller do not have learned the flow entry
    if (out_port != ofproto.OFPP_FLOOD):
      # add the flow entry to the controller directly
      match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
      # make sure to use the buffer_id for complete messaging between switch and controller
      if (msg.buffer_id != ofproto.OFP_NO_BUFFER):
        self.add_flow(datapath, 10, match, actions, msg.buffer_id)
        return
      else:
        self.add_flow(datapath, 10, match, actions)


    # if the packet now is an ARP packet
    if (ethernetFrame.ethertype == ETH_TYPE_ARP):
      arp_header = pkt.get_protocol(arp.arp)

      if (arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST):
        # reply the arp request direcly
        reply_packet = self.generate_arp_reply(arp_header.src_ip, arp_header.src_mac)
        actions = [parser.OFPActionOutput(in_port)]
        packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
        datapath.send_msg(packet_out)
        return

    if (ethernetFrame.ethertype == ETH_TYPE_IP):
      ip_header = pkt.get_protocol(ipv4.ipv4)
      packet_handled = self.handle_tcp_packet(datapath, in_port, ip_header, parser, dst_mac, src_mac)
      if (packet_handled):
        return

    data = None
    if (msg.buffer_id == ofproto.OFP_NO_BUFFER):
      data = msg.data

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
    
    datapath.send_msg(out)

  def generate_arp_reply(self, dst_ip, dst_mac):
    src_ip = self.VIRTUAL_IP

    # use round robin to select the server
    src_mac = self.current_server['mac']
    self.current_server = self.configured_servers[(self.current_index + 1) % len(self.configured_servers)]
    self.current_index = (self.current_index + 1) % len(self.configured_servers)

    pkt = packet.Packet()
    pkt.add_protocol(
      ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
    )
    pkt.add_protocol(
      arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
    )
    pkt.serialize()
    return pkt

  def handle_tcp_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):
    print(ip_header.dst)
    if (ip_header.dst != self.VIRTUAL_IP):
      return False

    # find the target server information
    target = next(item for item in self.configured_servers if item['mac'] == dst_mac)
    # if (len(target) > 0):
    server_dst_ip = target['ip']
    server_out_port = target['port']

    # route to the server directly
    match = parser.OFPMatch(
      in_port=in_port,
      eth_type=ETH_TYPE_IP,
      ip_proto=ip_header.proto,
      ipv4_dst=self.VIRTUAL_IP)
    actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip), parser.OFPActionOutput(server_out_port)]
    self.add_flow(datapath, 20, match, actions)

    # add reverse route to the flow table of the server
    match = parser.OFPMatch(
      in_port=server_out_port,
      eth_type=ETH_TYPE_IP,
      ip_proto=ip_header.proto,
      ipv4_src=server_dst_ip,
      eth_dst=src_mac)
    actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
    self.add_flow(datapath, 20, match, actions)
    return True
