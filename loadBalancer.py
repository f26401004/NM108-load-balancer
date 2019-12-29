from ryu import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

class LoadBalancer(app_manager.RyuApp):
  
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
  virtualIp = '10.0.1.1'

  configured_servers = []
  next_server = ''
  current_server = ''
  ip_to_port = {}
  ip_to_mac = {}

  def __init__(self, *args, **kwargs):
    super(LoadBalancer, self).__init__(*args, **kwargs)
    self.next_server = ''
    self.current_server = ''
    self.configured_servers = [{
      'ip': '10.0.0.1',
      'mac': ''
    }, {
      'ip': '10.0.0.2',
      'mac': ''
    }, {
      'ip': '10.0.0.3',
      'mac': ''
    }]

  # the function is called when a packet arrives from the swtich
  # and switch has no clues what to do with packet
  @set_ev_cls(ofp_event.EventOFPPacketIn, CONFIG_DISPATCHER)
  def packet_in_handler(self, event):
    msg = event.msg
    datapath = event.datapath
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser
    in_port = msg.match['in_port']

    packet = packet.Packet(msg.data)
    ethernetFrame = packet.get_protocol(ethernet.ethernet)

    self.mac_

    # if the packet received is an ARP response packet, then add
    # the ARP response information into flow table
    if ethernetFrame.ethertype == ether_types.ETH_TYPE_ARP:
      self.add_flow(datapath, packet, ofp_parser, ofp, in_port)
      # send ARP response to host
      self.arp_response(datapath, packet, ofp_parser, ofp, in_port)
      self.current_server = self.next_server
      return
    else:
      return

  # send an ARP response to the contacting host with the real MAC
  # address of a server
  def arp_response(self, datapath, packet, ethernetFrame, ofp_parser, ofp, in_port):
    arpPacket = packet.get_protocol(arp.arp)
    destinationIP = arpPacket.src_ip
    sourceIP = arpPacket.dst_ip
    destinationMAC = arpPacket.src
    sourceMAC = None

    # if the destination is not the configured server
    check = list(filter(lambda data: data.get('ip') == destinationIP))[0]
    if not check:
      # route the packet to the configured server
      if self.next_server == self.configured_servers[0]:
        sourceMAC = self.configured_servers[0].mac
        self.next_server = self.configured_servers[1].mac
      else:
        sourceMAC = self.configured_servers[1].mac
        self.next_server = self.configured_servers[0].mac
    else:
      # macth the MAC address from switch directly
      sourceMAC = self.ip_to_mac[sourceIP]

    # wrap up the packet
    tempEthernetFrame = etherent.ethernet(destinationMAC, sourceMAC, ether_types.ETH_TYPE_ARP)
    tempArpRequest = arp.arp(1, 0x0800, 6, 4, 2, sourceMAC, sourceIP. destinationMAC, destinationIP)

    tempPacket = Packet()
    tempPacket.add_protocol(tempEthernetFrame)
    tempPacket.add_protocol(tempArpRequest)
    tempPacket.serialize()

    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)]
    # wrap the whole action to Packet_out, and make switch execute the action
    output = ofp_parser.OFPPacketOut(
      datapath=datapath,
      buffer_id=ofp.OFP_NO_BUFFER,
      in_port=in_port,
      actions=actions,
      data=tempPacket.data
    )
    datapath.send_msg(output)

  # The function is called when receiving ARP response packet
  # to add the ARP response information into flow table of switch
  def add_flow(self, datapath, packet, ofp_parser, ofp, in_port):
    sourceIP = packet.get_protocol(arp.arp).src_ip

    # if the source is configired server, then just stop the aciton
    # to add the arp response into flow table of swtich
    check = list(filter(lambda data: data.get('ip') == sourceIP))[0]
    if check:
      # record the MAC address of the server
      check.mac = packet.get_protocol(arp.arp).src
      return
    
    match = ofp_parser.OFPMatch(in_port=in_port,
      ipv4_dst=self.virtualIp,
      eth_type=0x0800)
    actions = [ofp_parser.OFPActionSetField(ipv4_dst=self.current_server),
      ofp_parser.OFPActionOutput(self.ip_to_port[self.current_server])]
    instructions = [ofp_parser.OFPInstructionActions(ofp.OFP_APPLY_ACTIONS), actions]
  
    # write the flow entry into switch
    mod = ofp_parser.OFPFlowMod(
      datapath=datapath,
      priority=0,
      buffer_id=ofp.OPF_NO_BUFFER,
      match=match,
      instructions=instructions
    )
    datapath.send_msg(mod)

    # generate reverse flow from server to host
    match = ofp_parser.OFPMatch(in_port=self.ip_to_port[self.current_server],
      ipv4_src=self.current_server,
      ipv4_dst=sourceIP,
      eth_type=0x0800)
    actions = [ofp_parser.OFPActionSetField(ipv4_src=self.virtualIp),
      ofp_parser.OFPActionOutput(in_port)]
    instructions = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

    # write the flow entry into switch
    mod = ofp_parser.OFPFlowMod(
      datapath=datapath,
      priority=0,
      buffer_id=ofp.OPF_NO_BUFFER,
      match=match,
      instructions=instructions
    )
    datapath.send_msg(mod)
