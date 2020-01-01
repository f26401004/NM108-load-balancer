from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.topo import Topo

class LoadBalancerTopo(Topo):
  def __init__(self):
    Topo.__init__(self)

    # Add hosts
    host1 = self.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01', defaultRoute=None)
    host2 = self.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02', defaultRoute=None)
    host3 = self.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:03', defaultRoute=None)

    # Add clients
    client1 = self.addHost('c1', cls=Host, ip='10.0.0.4', mac='00:00:00:00:00:04', defaultRoute=None)
    client2 = self.addHost('c2', cls=Host, ip='10.0.0.5', mac='00:00:00:00:00:05', defaultRoute=None)
    client3 = self.addHost('c3', cls=Host, ip='10.0.0.6', mac='00:00:00:00:00:06', defaultRoute=None)
    client4 = self.addHost('c4', cls=Host, ip='10.0.0.7', mac='00:00:00:00:00:07', defaultRoute=None)

    # Add switches
    switch = self.addSwitch('s1', cls=OVSKernelSwitch)

    ## Add links
    self.addLink(host1, switch, 1, 1)
    self.addLink(host2, switch, 1, 2)
    self.addLink(host3, switch, 1, 3)
    self.addLink(client1, switch, 1, 4)
    self.addLink(client2, switch, 1, 5)
    self.addLink(client3, switch, 1, 6)
    self.addLink(client4, switch, 1, 7)

    # self.cmdPrint('h1 python -m SimpleHTTPServer 80')
    # self.cmdPrint('h2 python -m SimpleHTTPServer 80')
    # self.cmdPrint('h3 python -m SimpleHTTPServer 80')

topos = {
  'n1': (lambda: LoadBalancerTopo())
}