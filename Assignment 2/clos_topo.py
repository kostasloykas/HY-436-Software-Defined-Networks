  #!/usr/bin/python

from distutils import core
import logging
from site import addpackage
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
       
        # "Set up Core and Aggregate level, Connection Core - Aggregation level"
        tmp_cores = []
        for i in range(cores):
            tmp_cores.append("c" + str(i+1))
            
        cores = tmp_cores
        for i in cores:
            self.addSwitch(i)
            
        aggregates = []
        for i in range(len(cores)* fanout):
                aggregates.append("a" + str(len(cores)+i+1))

        for i in aggregates:
            self.addSwitch(i)

        for i in aggregates:
            for j in cores:
                self.addLink(i,j)

        # "Set up Edge level, Connection Aggregation - Edge level "
        edges = []
        for i in range(len(aggregates) * fanout):
                edges.append("e" + str(len(cores)+len(aggregates)+i+1))

        for i in edges:
            self.addSwitch(i)

        for i in edges:
            for j in aggregates:
                self.addLink(i,j)

        
        # "Set up Host level, Connection Edge - Host level "
        hosts = []
        for i in range(len(edges) * fanout):
            hosts.append("h" + str(i+1))

        for i in hosts:
            self.addHost(i)

        host_iter = iter(hosts)
        for i in edges:
            for j in range(fanout):
                self.addLink(i,next(host_iter))



def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])