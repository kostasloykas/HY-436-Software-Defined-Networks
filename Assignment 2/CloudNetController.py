#generic imports
import random
import csv

#pox-specific imports
from pox.core import core
from pox.openflow import ethernet
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.packet.tcp import tcp
from pox.lib.packet.ipv4 import ipv4


#networkx import for graph management
import networkx as nx

#for beautiful prints of dicts, lists, etc,
from pprint import pprint as pp

log = core.getLogger()

MAX_PHYS_PORTS = 0xFF00

# dict of TCP and UDP proto numbers
PROTO_NUMS = {
  6 : 'tcp',
  17: 'udp/other'
}

ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")
ETHER_ANY            = EthAddr(b"\x00\x00\x00\x00\x00\x00")
TCP = 6
UDP = 17
ICMP = 1



class CloudNetController (EventMixin):

    _neededComponents = set(['openflow_discovery'])

    def __init__(self, firewall_capability, migration_capability, firewall_policy_file, migration_events_file):
        super(EventMixin, self).__init__()

        #generic controller information
        self.switches = {}     # key=dpid, value = SwitchWithPaths instance
        self.sw_sw_ports = {}  # key = (dpid1,dpid2), value = outport of dpid1
        self.adjs = {}         # key = dpid, value = list of neighbors
        self.arpmap = {} # key=host IP, value = (mac,dpid,port)
        self._paths_computed = False #boolean to indicate if all paths are computed (converged routing)
        self.ignored_IPs = [IPAddr("0.0.0.0"), IPAddr("255.255.255.255")] #these are used by openflow discovery module

        #invoke event listeners
        if not core.listen_to_dependencies(self, self._neededComponents):
            self.listenTo(core)
        self.listenTo(core.openflow)

        #module-specific information
        self.firewall_capability = firewall_capability
        self.migration_capability = migration_capability
        self.firewall_policies = None
        self.migration_events = None
        self.migrated_IPs = None
        if self.firewall_capability:
            self.firewall_policies = self.read_firewall_policies(firewall_policy_file)
            print(self.firewall_policies)
        if self.migration_capability:
            self.migration_events = self.read_migration_events(migration_events_file)
            self.old_migrated_IPs = {} #key=old_IP, value=new_IP
            self.new_migrated_IPs = {} #key=new_IP, value=old_IP
            for event in self.migration_events:
                migration_time = event[0]
                old_IP = event[1]
                new_IP = event[2]
                Timer(migration_time, self.handle_migration, args = [IPAddr(old_IP), IPAddr(new_IP)])

    def read_firewall_policies(self, firewall_policy_file):
        firewall_policies = {}
        with open(firewall_policy_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                tenant_id = row[0]
                for ip in row[1:len(row)]:
                    firewall_policies[IPAddr(ip)] = int(tenant_id)
        return firewall_policies

    def read_migration_events(self, migration_info_file):
        migration_events = []
        with open(migration_info_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                migration_time = int(row[0])
                old_ip = IPAddr(row[1])
                new_ip = IPAddr(row[2])
                migration_events.append((migration_time, old_ip, new_ip))
        return migration_events

    def _handle_ConnectionUp(self, event):
        if event.dpid not in self.switches:
            self.switches[event.dpid] = SwitchWithPaths()
            if event.dpid not in self.adjs:
                self.adjs[event.dpid] = set([])
        self.switches[event.dpid].connect(event.connection)
        #send unknown ARP and IP packets to controller (install rules for that with low priority)
        msg_ARP = of.ofp_flow_mod()
        msg_IP  = of.ofp_flow_mod()
        msg_ARP.match.dl_type = 0x0806
        msg_IP.match.dl_type  = 0x0800
        msg_ARP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        msg_IP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        msg_ARP.priority = of.OFP_DEFAULT_PRIORITY - 1
        msg_IP.priority  = of.OFP_DEFAULT_PRIORITY - 1
        event.connection.send(msg_ARP)
        event.connection.send(msg_IP)

    def _handle_ConnectionDown(self, event):
        ips_to_forget = []
        for ip in self.arpmap:
            (mac, dpid, port) = self.arpmap[ip]
            if dpid == event.dpid:
                ips_to_forget.append(ip)
        for ip in ips_to_forget:
            del self.arpmap[ip]
        if (event.dpid in self.switches):
            self.switches[event.dpid].disconnect()
            del self.switches[event.dpid]
        #let the discovery module deal with the port removals...

    def flood_on_all_switch_edges(self, packet, this_dpid, this_port):
        for src_dpid in self.switches:
            no_flood_ports = set([]) #list of non-flood ports
            if src_dpid in self.adjs:
                for nei_dpid in self.adjs[src_dpid]:
                    no_flood_ports.add(self.sw_sw_ports[(src_dpid,nei_dpid)])
            if src_dpid == this_dpid:
                no_flood_ports.add(this_port)
            self.switches[src_dpid].flood_on_switch_edge(packet, no_flood_ports)

    def update_learned_arp_info(self, packet, dpid, port):
        src_ip = None
        src_mac = None
        if packet.type == packet.ARP_TYPE:
            src_mac = EthAddr(packet.src)
            src_ip  = IPAddr(packet.next.protosrc)
        elif packet.type == packet.IP_TYPE:
            src_mac = EthAddr(packet.src)
            src_ip  = IPAddr(packet.next.srcip)
        else:
            pass
        if (src_ip != None) and (src_mac != None):
            self.arpmap[src_ip] = (src_mac, dpid, port)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        inport = event.port

        def handle_ARP_pktin():
            srcip = IPAddr(packet.next.protosrc)
            dstip = IPAddr(packet.next.protodst)
            if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
                return
            

            if packet.next.opcode == arp.REQUEST:
                log.info("Handling ARP packet: %s requests the MAC of %s" % (str(srcip), str(dstip)))
                self.update_learned_arp_info(packet, dpid, inport)

                #FIREWALL functionality
                if self.firewall_capability:
                    try:

                        if(self.CommunicationIsNotValid(dpid=dpid,srcip=srcip,dstip=dstip,packet=packet)):
                            return
                        pass
                    except KeyError:
                        log.info("IPs not covered by policy!")
                        return

                if self.migration_capability:
                    #ignore ARP requests coming from old migrated IPs or directed to new ones
                    if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
                        return

                if dstip in self.arpmap:
                    log.info("I know where to send the crafted ARP reply!")
                    (req_mac, req_dpid, req_port) = self.arpmap[dstip]
                    (dst_mac, dst_dpid, dst_port) = self.arpmap[srcip]
                    self.switches[dst_dpid].send_arp_reply(packet, dst_port, req_mac)
                else:
                    log.info("Flooding initial ARP request on all switch edges")
                    self.flood_on_all_switch_edges(packet, dpid, inport)

            elif packet.next.opcode == arp.REPLY:
                log.info("Handling ARP packet: %s responds to %s" % (str(srcip), str(dstip)))
                self.update_learned_arp_info(packet, dpid, inport)

                #FIREWALL functionality
                if self.firewall_capability:
                    try:

                        if(self.CommunicationIsNotValid(dpid=dpid,srcip=srcip,dstip=dstip,packet=packet)):
                            return
                        pass
                    except KeyError:
                        return

                if self.migration_capability:
                    #ignore ARP replies coming from old migrated IPs or directed to new ones
                    if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
                        return

                if dstip in self.arpmap.keys():
                    log.info("I know where to send the initial ARP reply!")
                    (dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
                    self.switches[dst_dpid].send_packet(dst_port, packet)
                else:
                    log.info("Flooding initial ARP reply on all switch edges")
                    self.flood_on_all_switch_edges(packet,dpid,inport)
            else:
                log.info("Unknown ARP type")
                return

        def handle_IP_pktin():
            srcip = IPAddr(packet.next.srcip)
            dstip = IPAddr(packet.next.dstip)
            if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
                return

            log.info("Handling IP packet between %s and %s" % (str(srcip), str(dstip)))

            #FIREWALL functionality
            if self.firewall_capability:
                try:
                    if(self.CommunicationIsNotValid(dpid=dpid,srcip=srcip,dstip=dstip,packet=packet)):
                        # install rule
                        return
                    pass
                except KeyError:
                    log.info("IPs not covered by policy!")
                    return

            if self._paths_computed:
                #print "Routing calculations have converged"
                log.info("Path requested for flow %s-->%s" % (str(srcip), str(dstip)))

                if dstip in self.arpmap: #I know where to send the packet
                    (dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]

                    #MIGRATION functionality
                    if self.migration_capability:
                        #IP packet goes to old server after migration is done
                        if dstip in self.old_migrated_IPs:
                            (dst_mac, dst_dpid, dst_port) = self.arpmap[self.old_migrated_IPs[dstip]]
                            #install path to new server and change packet headers
                            log.info("Installing migrated forward path towards: old IP: %s, new IP: %s" % (str(dstip), str(self.old_migrated_IPs[dstip])))
                            self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=True)
                            log.info("Forward migrated path installed")

                        #IP packet comes from new server after migration is done
                        elif srcip in self.new_migrated_IPs:
                            (dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
                            log.info("Installing migrated reverse path from: old IP: %s, new IP: %s" % (str(srcip), str(self.new_migrated_IPs[srcip])))
                            self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=False)
                            log.info("Reverse migrated path installed")
                        else:
                            self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
                    else:
                        self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
                else:
                    self.flood_on_all_switch_edges(packet, dpid, inport)
            else:
                print ("Routing calculations have not converged, discarding packet")
                return

        #--------------------------------------------------------------------------------------------------------------
        if packet.type == packet.LLDP_TYPE:
            return

        elif packet.type == packet.ARP_TYPE:
            handle_ARP_pktin()
            return

        elif packet.type == packet.IP_TYPE:
            handle_IP_pktin()

            return

        else:
            #log.info("Unknown Packet type: %s" % packet.type)
            return


    def CommunicationIsNotValid(self, srcip, dstip , dpid , packet):
        # if hosts are not in the same tenant install flow rule to drop
        # packet and finally drop the real packet from the controller 

        if(self.HostsAreNotInTheSameTenant(srcip,dstip)):
            print("Host {} and host {} are not in the same tenant".format(srcip , dstip))
            self.drop_packets(dpid , packet)
            print("Packet dropped and a drop flow rule installed in the switch {}".format(dpid))
            return True
        # else hosts are in the same tenant so allow exchange packet
        return False

    def HostsAreNotInTheSameTenant(self,srcip,dstip):
        return bool(self.firewall_policies[srcip] != self.firewall_policies[dstip])


    def SwitchThatTriggeredIsTheDestinationSwitch(self, switch_dpid , dst_dpid):
        return bool(switch_dpid == dst_dpid)


    def install_end_to_end_IP_path(self, event, dst_dpid, final_port, packet):
        protocol = packet.payload.protocol
        src_ip = packet.payload.srcip
        dst_ip = packet.payload.dstip
        print("Protocol is {}".format(protocol))
        print("Ip path from switch {} to switch {}".format(event.dpid,dst_dpid))
        
        # We install a flow rule on a switch, but the installation is not performed immediately. 
        # Therefore, a number of PacketIn events might be triggered on the same switch 
        # until the flow rule has finally been installed
        if self.SwitchThatTriggeredIsTheDestinationSwitch( event.dpid , dst_dpid):
            self.switches[dst_dpid].install_output_flow_rule( outport = final_port , match = of.ofp_match(dl_type = 0x0800 , 
                                                                nw_src = src_ip ,nw_dst = dst_ip), idle_timeout = 10)
            self.switches[dst_dpid].send_packet(outport = final_port, packet_data = packet)
            return


        # choose random path taking into account the transport protocol
        random_path = list(self.ChooseRandomPath(event,protocol,dst_dpid))

        print("Random path = ",random_path)
        print("All paths is {}".format(self.switches[event.dpid]._paths[dst_dpid]))
        random_path.reverse()

        
        # install flow rules for each switch
        for i,switch_dpid in enumerate(random_path):
            # install rule for final switch
            if switch_dpid == dst_dpid:
                print("install fisrt flow rule for switch={}".format(switch_dpid))
                # ip protocol is 0x0800
                self.switches[switch_dpid].install_output_flow_rule( outport = final_port , match = of.ofp_match(dl_type = 0x0800 , 
                nw_src = src_ip ,nw_dst = dst_ip), idle_timeout = 10)
            else:
                print("install other flow rule for switch={}".format(switch_dpid))
                prev_switch = random_path[i-1]
                self.switches[switch_dpid].install_output_flow_rule( outport = self.sw_sw_ports[(switch_dpid,prev_switch)] , match = of.ofp_match(dl_type = 0x0800 ,
                                        nw_src = src_ip ,nw_dst = dst_ip), idle_timeout = 10)
            
                
        random_path.reverse()
        assert len(random_path) >=1

        # after install all flow rules we send the packet
        # to the source switch that the packet came from
        if (len(random_path)==1):
            self.switches[event.dpid].send_packet(outport = self.sw_sw_ports[(event.dpid,random_path[0])], packet_data = packet)
        else:
            self.switches[event.dpid].send_packet(outport = self.sw_sw_ports[(event.dpid,random_path[1])], packet_data = packet)

        pass

    
        
    def ChooseRandomPath(self,event,protocol,dst_dpid):
        random_path = None

        # if protocol is icmp then select UDP path
        if protocol == ICMP: protocol = UDP

        if protocol == TCP or protocol == UDP:
            random_path = random.choice(self.switches[event.dpid]._paths_per_proto[dst_dpid][protocol])
        #  if packet protocol isn't tcp or udp

        assert random_path != None
        return random_path


    # def MakePacketSYN(self,packet,new_mac,new_ip):
    #     tcp_syn_packet = tcp(srcport=packet.payload.payload.srcport , dstport=packet.payload.payload.dstport , off=5 ,flags = tcp.SYN_flag)
    #     ipv4_packet = ipv4()
    #     ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_syn_packet)
    #     ipv4_packet.protocol = ipv4.TCP_PROTOCOL
    #     ipv4_packet.dstip = IPAddr(new_ip)
    #     ipv4_packet.srcip = IPAddr(packet.payload.srcip)
    #     ipv4_packet.set_payload(tcp_syn_packet.pack())
    #     ether = ethernet(type = ethernet.IP_TYPE , src=packet.src , dst = new_mac, payload = ipv4_packet.pack())
    #     return ether
        
    # def MakePacketACK(self,packet):
    #     tcp_ack_packet = tcp(srcport=packet.payload.payload.dstport , dstport=packet.payload.payload.srcport , seq=1 ,
    #     ack=1 , off=5 ,flags = tcp.ACK_flag)
    #     ipv4_packet = ipv4()
    #     ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_ack_packet)
    #     ipv4_packet.protocol = ipv4.TCP_PROTOCOL
    #     ipv4_packet.dstip = IPAddr(packet.payload.srcip)
    #     ipv4_packet.srcip = IPAddr(packet.payload.dstip)
    #     ipv4_packet.set_payload(tcp_ack_packet)
    #     ether = ethernet(type = ethernet.IP_TYPE , src=packet.dst , dst = packet.src, payload = ipv4_packet)
    #     return ether

    def install_migrated_end_to_end_IP_path(self, event, dst_dpid, dst_port, packet, forward_path=True):
        protocol = packet.payload.protocol
        src_ip = packet.payload.srcip
        dst_ip = packet.payload.dstip
        print("Protocol is {}".format(protocol))
        print("Migrated IP path from switch {} to switch {} ".format(event.dpid,dst_dpid))

        # choose random path taking into account the transport protocol
        random_path = list(self.ChooseRandomPath(event,protocol,dst_dpid))

        print("Random path = ",random_path)
        print("All paths is {}".format(self.switches[event.dpid]._paths[dst_dpid]))
        random_path.reverse()

        # Forward=True means that packetIn raised from the switch that a host ping
        if forward_path:
            new_ip = self.old_migrated_IPs[dst_ip]
            (new_mac, new_dpid, new_port) = self.arpmap[new_ip]
            #  for all switches in path except this switch that raised packetIn event
            for i,dpid in enumerate(random_path[:-1]):
                if i==0:
                    self.switches[dpid].install_output_flow_rule( outport =  dst_port,
                            match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = new_ip), idle_timeout = 10)
                else:
                    # install rule for other switches in path
                    prev_switch = random_path[i-1]
                    self.switches[dpid].install_output_flow_rule( outport =  self.sw_sw_ports[(dpid,prev_switch)],
                            match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = new_ip), idle_timeout = 10)
                pass


            random_path.reverse()
            # must be greater than 1 because we would have catch it at the start of function  
            assert len(random_path) >= 1

            
            if len(random_path) == 1:
                # install rule for the switch that rewrites headers
                self.switches[event.dpid].install_forward_migration_rule(outport = dst_port,
                                match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = dst_ip ), dst_ip = new_ip ,
                                dst_mac = new_mac , idle_timeout = 10)
                
                # after the installation of flow rules we send the packet
                self.switches[event.dpid].send_forward_migrated_packet(outport = dst_port,
                dst_mac = new_mac ,dst_ip = new_ip ,packet_data = packet )
                
            else:
                self.switches[event.dpid].install_forward_migration_rule(outport = self.sw_sw_ports[(event.dpid,random_path[1])],
                                match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = dst_ip ), dst_ip = new_ip ,
                                dst_mac = new_mac , idle_timeout = 10)

                # after the installation of flow rules we send the packet
                self.switches[event.dpid].send_forward_migrated_packet(outport = self.sw_sw_ports[(event.dpid,random_path[1])],
                dst_mac = new_mac ,dst_ip = new_ip ,packet_data = packet )
                

                
        # Forward=False means that packetIn raised from the switch of migrated host
        # Reverse Path
        else:
            new_ip = self.new_migrated_IPs[src_ip]
            (new_mac, new_dpid, new_port) = self.arpmap[new_ip]

            for i,dpid in enumerate(random_path[:-1]):
               # install rule for final switch
                if i == 0:
                    self.switches[dpid].install_output_flow_rule( outport = dst_port,
                            match = of.ofp_match(dl_type = 0x0800 , nw_src = new_ip ,nw_dst = dst_ip), idle_timeout = 10)                    
                # install rule for other switches in path
                else:
                    prev_switch = random_path[i-1]
                    self.switches[dpid].install_output_flow_rule( outport =  self.sw_sw_ports[(dpid,prev_switch)],
                            match = of.ofp_match(dl_type = 0x0800 , nw_src = new_ip ,nw_dst = dst_ip), idle_timeout = 10)                    
                    pass

            random_path.reverse()

            # must be greater than 1 because we would have catch it at the start of function  
            assert len(random_path) >= 1 

            if len(random_path) == 1:
                # install rule for the switch that rewrites headers
                self.switches[event.dpid].install_reverse_migration_rule(outport = dst_port,
                                match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = dst_ip ), src_ip = new_ip ,
                                src_mac = new_mac , idle_timeout = 10)

                # after the installation of flow rules we send the packet
                self.switches[event.dpid].send_reverse_migrated_packet(outport = dst_port
                , src_mac = new_mac, src_ip = new_ip, packet_data = packet)
            else:
                self.switches[event.dpid].install_reverse_migration_rule(outport = self.sw_sw_ports[(event.dpid,random_path[1])],
                                match = of.ofp_match(dl_type = 0x0800 , nw_src = src_ip ,nw_dst = dst_ip ), src_ip = new_ip ,
                                src_mac = new_mac , idle_timeout = 10)

                # after the installation of flow rules we send the packet
                self.switches[event.dpid].send_reverse_migrated_packet(outport = self.sw_sw_ports[(event.dpid,random_path[1])]
                , src_mac = new_mac, src_ip = new_ip, packet_data = packet)

        return

    def handle_migration(self, old_IP, new_IP):
        log.info("Handling migration from %s to %s..." % (str(old_IP), str(new_IP)))
        # create ofp_flow_mod message to delete all flows
        # to the destination to be migrated
        msg_1 = of.ofp_flow_mod()
        match_1 = of.ofp_match()
        match_1.dl_type = 0x0800
        match_1.nw_dst = old_IP
        msg_1.match = match_1
        msg_1.command = of.OFPFC_DELETE
        # create ofp_flow_mod message to delete all flows
        # coming from the source that will host the migrated one
        msg_2 = of.ofp_flow_mod()
        match_2 = of.ofp_match()
        match_2.dl_type = 0x0800
        match_2.nw_src = new_IP
        msg_2.match = match_2
        msg_2.command = of.OFPFC_DELETE
        # send the ofp_flow_mod messages to all switches
        # leading to the destination to be migrated (or coming from the source that will host it)
        for sw in self.switches:
            self.switches[sw].connection.send(msg_1)
            log.info("Rules having as dest %s removed at switch: %i" % (str(old_IP), sw))
            self.switches[sw].connection.send(msg_2)
            log.info("Rules having as source %s removed at switch: %i" % (str(new_IP), sw))
        log.info("Rules deleted, now new IP e2e paths will be automatically migrated to the new IP %s" % (str(new_IP)))
        self.old_migrated_IPs[old_IP] = new_IP
        self.new_migrated_IPs[new_IP] = old_IP
        (new_mac, new_dpid, new_inport) = self.arpmap[self.old_migrated_IPs[old_IP]]
        # the migrated host will have the mac and ip of new host
        self.arpmap[old_IP] = (new_mac, new_dpid, new_inport)
        log.info("Arpmap for old ip updated")

    def drop_packets(self, dpid, packet):
        match = of.ofp_match.from_packet(packet)
        self.switches[dpid].install_drop_flow_rule(match, idle_timeout=0, hard_timeout=0)

    def _handle_openflow_discovery_LinkEvent(self, event):
        self._paths_computed = False
        link = event.link
        dpid1 = link.dpid1
        port1 = link.port1
        dpid2 = link.dpid2
        port2 = link.port2
        if dpid1 not in self.adjs:
            self.adjs[dpid1] = set([])
        if dpid2 not in self.adjs:
            self.adjs[dpid2] = set([])

        if event.added:
            self.sw_sw_ports[(dpid1,dpid2)] = port1
            self.sw_sw_ports[(dpid2,dpid1)] = port2
            self.adjs[dpid1].add(dpid2)
            self.adjs[dpid2].add(dpid1)
        else:
            if (dpid1,dpid2) in self.sw_sw_ports:
                del self.sw_sw_ports[(dpid1,dpid2)]
            if (dpid2,dpid1) in self.sw_sw_ports:
                del self.sw_sw_ports[(dpid2,dpid1)]
            if dpid2 in self.adjs[dpid1]:
                self.adjs[dpid1].remove(dpid2)
            if dpid1 in self.adjs[dpid2]:
                self.adjs[dpid2].remove(dpid1)

        print ("Current switch-to-switch ports:")
        pp(self.sw_sw_ports)
        print ("Current adjacencies:")
        pp(self.adjs)
        self._paths_computed=False
        self.checkPaths()
        if self._paths_computed == False:
            print ("Warning: Disjoint topology, Shortest Path Routing converging")
        else:
            print ("Topology connected, Shortest paths (re)computed successfully, Routing converged")
            print ("--------------------------")
            for dpid in self.switches:
                self.switches[dpid].printPaths()
            print ("--------------------------")

    def checkPaths(self):
        if not self._paths_computed:
            self._paths_computed = ShortestPaths(self.switches, self.adjs)
        return self._paths_computed

    def __str__(self):
        return "Cloud Network Controller"


class SwitchWithPaths (EventMixin):
    def __init__(self):
        self.connection = None
        self.dpid = None
        self.ports = None
        self._listeners = None
        self._paths = {}
        self._paths_per_proto = {}

    def __repr__(self):
        return str(self.dpid)

    def appendPaths(self, dst, paths_list):
        if dst not in self._paths:
            self._paths[dst] = []
        self._paths[dst] = paths_list
        self.getPathsperProto(dst)

    def clearPaths(self):
        self._paths = {}
        self._paths_per_proto = {}

    def getPathsperProto(self, dst):
        self._paths_per_proto[dst] = {}
        # populate the per-protocol paths
        list_of_proto_nums = sorted(list(PROTO_NUMS.keys()))
        for proto_num in list_of_proto_nums:
            self._paths_per_proto[dst][proto_num] = []         
        for i,path in enumerate(self._paths[dst]):
            proto_num = list_of_proto_nums[i % len(PROTO_NUMS)]
            self._paths_per_proto[dst][proto_num].append(self._paths[dst][i])
        # if no paths for a specific protocol, get one from the pool randomly
        for proto_num in list_of_proto_nums:
            if len(self._paths_per_proto[dst][proto_num]) == 0:
                self._paths_per_proto[dst][proto_num] = [random.choice(self._paths[dst])]

    def printPaths(self):
        for dst in self._paths:
            equal_paths_number = len(self._paths[dst])
            if equal_paths_number > 1:
                print ("There are %i shortest paths from switch %i to switch %i:" % (equal_paths_number, self.dpid, dst))
            else:
                print ("There is exactly one shortest path from switch %i to switch %i:" % (self.dpid, dst))
            for proto_num in self._paths_per_proto[dst]:
                print ("---%s (%s) paths---" % (str(PROTO_NUMS[proto_num]), str(proto_num)))
                for path in self._paths_per_proto[dst][proto_num]:
                    for u in path:
                         print ("%i," % (u),)
                    print ("")


    def connect(self, connection):
        if self.dpid is None:
            self.dpid = connection.dpid
        assert(self.dpid == connection.dpid)
        if self.ports is None:
            self.ports = connection.features.ports
        log.info("Connect %s" % (connection))
        self.connection = connection
        self._listeners = self.listenTo(connection)

    def disconnect(self):
        if self.connection is not None:
            log.info("Disconnect %s" % (self.connection))
            self.connection.removeListeners(self._listeners)
            self.connection = None
            self._listeners = None

    def flood_on_switch_edge(self, packet, no_flood_ports):
        all_ports_of_switch = []
        for i in self.ports:
            all_ports_of_switch.append(i.port_no)

        ether = ethernet(type = packet.type , src=packet.src , dst = packet.dst, payload=packet.payload)

        # for every valid port send the arp request to the right switch
        # The packet send from the dpid port (in controller) to the right switch 
        for i in list(set(all_ports_of_switch) - set(no_flood_ports)):
            msg = of.ofp_packet_out(in_port = self.dpid , data = ether.pack() , actions = of.ofp_action_output(port = i))
            self.connection.send(msg)

        pass

    def send_packet(self, outport, packet_data=None):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.data = packet_data
        msg.actions.append(of.ofp_action_output(port=outport))
        self.connection.send(msg)

    def send_arp_reply(self, packet, dst_port, req_mac):
        
        arp_reply = arp(opcode=arp.REPLY , hwsrc=req_mac , hwdst=packet.next.hwsrc , protodst=packet.next.protosrc ,
                        protosrc=packet.next.protodst)
        ether = ethernet(type=ethernet.ARP_TYPE , dst=packet.src , src=req_mac , payload=arp_reply)
        msg = of.ofp_packet_out( data=ether.pack() , actions=of.ofp_action_output(port = dst_port))
        self.connection.send(msg)

        pass

    def install_output_flow_rule(self, outport, match, idle_timeout=0, hard_timeout=0):
        msg=of.ofp_flow_mod()
        msg.match = match
        msg.command = of.OFPFC_MODIFY_STRICT
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        msg.actions.append(of.ofp_action_output(port=outport))
        self.connection.send(msg)

    def install_drop_flow_rule(self, match, idle_timeout=0, hard_timeout=0):
        msg=of.ofp_flow_mod()
        msg.match = match
        msg.command = of.OFPFC_MODIFY_STRICT
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        msg.actions = [] #empty action list for dropping packets
        self.connection.send(msg)

    def send_forward_migrated_packet(self, outport, dst_mac, dst_ip, packet_data=None):
        assert packet_data != None
        packet_data.dst = dst_mac
        packet_data.payload.dstip = dst_ip
        self.send_packet(outport=outport , packet_data=packet_data)
        pass

    def send_reverse_migrated_packet(self, outport, src_mac, src_ip, packet_data=None):
        assert packet_data != None
        packet_data.src = src_mac
        packet_data.payload.srcip = src_ip
        self.send_packet(outport=outport , packet_data=packet_data)
        pass
        
    def install_forward_migration_rule(self, outport, dst_mac, dst_ip, match, idle_timeout=0, hard_timeout=0):
        msg = of.ofp_flow_mod(command =  of.OFPFC_ADD, idle_timeout = idle_timeout , hard_timeout = hard_timeout , match = match , 
                            actions= [ of.ofp_action_nw_addr().set_dst(dst_ip) , of.ofp_action_dl_addr().set_dst(dst_mac) ,
                            of.ofp_action_output(port = outport)])
        self.connection.send(msg)
        pass

    def install_reverse_migration_rule(self, outport, src_mac, src_ip, match, idle_timeout=0, hard_timeout=0):
        msg = of.ofp_flow_mod(command =  of.OFPFC_ADD, idle_timeout = idle_timeout , hard_timeout = hard_timeout , match = match , 
                            actions= [ of.ofp_action_nw_addr().set_src(src_ip) , of.ofp_action_dl_addr().set_src(src_mac) ,
                            of.ofp_action_output(port = outport)])
        self.connection.send(msg)
        pass


def MakeGraph(switches,adjs):
    graph = nx.Graph()
    switches = dict(switches)
    
    for i in switches:
        graph.add_node(i)

    for i,j in dict(adjs).items():
        for neighbor in list(j):
            if not graph.has_edge(i,neighbor):
                graph.add_edge(i,neighbor)

    return graph


def  FindMinimunPathsFrom_i_to_j(paths):
    min_length = 100

    for i in paths:
        if len(i) < min_length:
            min_length = len(i)
    
    assert min_length != 100
    return [i for i in paths if len(i) == min_length]



def ShortestPaths(switches, adjs):

    graph = MakeGraph(switches,adjs)
    for src in switches:
        for dst in switches:
            paths = []
            try:
                tmp = list(nx.all_shortest_paths(graph,src,dst))
                paths = FindMinimunPathsFrom_i_to_j(tmp)
            except nx.NetworkXNoPath:
                #  No path from i switch to j switch
                return False
            switches[src].appendPaths(dst,paths)
    return True 
    

    
def str_to_bool(str):
    assert(str in ['True', 'False'])
    if str=='True':
        return True
    else:
        return False

        
def launch(firewall_capability='True', migration_capability='True',
           firewall_policy_file='./ext/firewall_policies.csv', migration_events_file='./ext/migration_events.csv'):
    """
    Args:
        firewall_capability  : boolean, True/False
        migration_capability : boolean, True/False
        firewall_policy_file : string, filename of the csv file with firewall policies
        migration_info_file  : string, filename of the csv file with migration information
    """
    log.info("Loading Cloud Network Controller")
    firewall_capability = str_to_bool(firewall_capability)
    log.info("Firewall Capability enabled: %s" % (firewall_capability))
    migration_capability = str_to_bool(migration_capability)
    log.info("Migration Capability enabled: %s" % (migration_capability))
    core.registerNew(CloudNetController, firewall_capability, migration_capability, firewall_policy_file, migration_events_file)
    log.info("Network Controller loaded")
