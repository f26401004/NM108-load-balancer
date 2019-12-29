from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.topo import Topo

class LoadBalancerTopo(Topo):
  def __init__(self):
    Topo.__init__(self)

    # Add hosts
    host1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    host2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    host3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)

    # Add clients
    client1 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    client2 = self.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    client3 = self.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)
    client4 = self.addHost('h7', cls=Host, ip='10.0.0.7', defaultRoute=None)

    # Add switches
    switch = self.addSwitch('s1', cls=OVSKernelSwitch)

    ## Add links
    self.addLink(host1, switch)
    self.addLink(host2, switch)
    self.addLink(host3, switch)
    self.addLink(host4, switch)
    self.addLink(host5, switch)
    self.addLink(host6, switch)
    self.addLink(host7, switch)

topos = {
  'n1': (lambda: LoadBalancerTopo())
}