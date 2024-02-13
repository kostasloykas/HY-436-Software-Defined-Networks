from pickle import FALSE, NONE, TRUE
from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IP_BROADCAST, EthAddr, IPAddr
log = core.getLogger()
import random
import json # addition to read configuration from file

ETHER_BROADCAST = EthAddr(b"\xff\xff\xff\xff\xff\xff")
ETHER_ANY = EthAddr(b"\x00\x00\x00\x00\x00\x00")


class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):

        # add the necessary openflow listeners
        core.openflow.addListeners(self) 

        # set class parameters
        self.lb_mac = lb_mac
        self.service_ip=service_ip
        self.server_ips = server_ips
        self.user_ip_to_group=user_ip_to_group
        self.server_ip_to_group = server_ip_to_group
        self.servers_ip_to_mac_ports={}
        self.clients_ip_to_mac_ports={}
        self.installed_rules_for_clients= set() #set for installed rules of clients
        self.installed_rules_for_servers= set() #set for installed rules of servers with specific clients
        pass


    
    

    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.info("Connection Up")
        print("Sending arp request in order to learn about other machines in network")
        
        for x in self.server_ips:
            self.send_proxied_arp_request(self.connection , x)

        pass
    

    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip,buffer_id):
        color = self.GetClientsColor(client_ip)
        server_ip = self.ChooseRandomServer(color)
        log.info("Update Map for Client with ip {} and Server with ip {}".format(client_ip,server_ip))
        outport = self.servers_ip_to_mac_ports[server_ip][1] # server's port

        # update (modify) the rule of client and change the ip
        # buffer_id needs in order to start the rule from there
        self.connection.send(of.ofp_flow_mod(command=of.ofp_flow_mod_command_rev_map["OFPFC_MODIFY"] ,
                            actions=( of.ofp_action_dl_addr().set_dst(self.servers_ip_to_mac_ports[server_ip][0]),
                            of.ofp_action_nw_addr().set_dst(server_ip) , of.ofp_action_nw_addr().set_src(client_ip) ,
                            of.ofp_action_dl_addr().set_src(self.clients_ip_to_mac_ports[client_ip][0]),
                            of.ofp_action_output(port=outport)) , buffer_id=buffer_id , idle_timeout=10 ,
                            match=of.ofp_match(dl_type=0x800,nw_src=client_ip,nw_dst=self.service_ip)))
        pass 
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        print("Send Arp Reply to {}".format(requested_mac))

        ether = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac,dst=requested_mac)
        ether.set_payload(packet)

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)
        pass

    
    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        print("Send Arp Request to {}".format(ip))

        #construct arp packet
        packet = arp()
        packet.hwtype = packet.HW_TYPE_ETHERNET
        packet.prototype = packet.PROTO_TYPE_IP
        packet.hwsrc = self.lb_mac
        packet.opcode = packet.REQUEST
        packet.protosrc = self.service_ip
        packet.protodst = ip

        #load packet in ethernet
        ether = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac,dst=ETHER_BROADCAST)
        ether.set_payload(packet)

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)
        pass

    
    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        log.info("Install Flow Rule for Client {} To Server {}".format(client_ip , server_ip))

        # no wildcards
        # We use buffer_id to directly the rule start from there 
        connection.send(of.ofp_flow_mod(actions=( of.ofp_action_dl_addr().set_dst(self.servers_ip_to_mac_ports[server_ip][0]) ,
                         of.ofp_action_dl_addr().set_src(self.lb_mac) , of.ofp_action_nw_addr().set_dst(server_ip) , of.ofp_action_nw_addr().set_src(client_ip) , 
                         of.ofp_action_output(port=outport)) , idle_timeout=10, buffer_id=buffer_id , command=of.OFPFC_ADD ,
                        match=of.ofp_match(dl_type=0x800,nw_src=client_ip , nw_dst=self.service_ip)))
        pass


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        log.info("Install Flow Rule for Server {} To Client {}".format(client_ip , server_ip))
        
        # no wildcards
        connection.send(of.ofp_flow_mod(actions=(of.ofp_action_nw_addr().set_dst(client_ip),
                        of.ofp_action_nw_addr().set_src(self.service_ip) , of.ofp_action_dl_addr().set_src(self.lb_mac) , 
                        of.ofp_action_dl_addr().set_dst(self.clients_ip_to_mac_ports[client_ip][0]) , of.ofp_action_output(port=outport)), idle_timeout=10 ,
                        command=of.OFPFC_ADD , buffer_id=buffer_id , match=of.ofp_match(dl_type=0x800,nw_src=server_ip , nw_dst=client_ip)))
                        
        pass

    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        log.info("Handle Packet In")
        packet = event.parsed
        connection = event.connection
        self.connection = connection
        inport = event.port
        buffer_id=event.ofp.buffer_id

        self.CheckIfPacketIsFromClientAndStoreMacAndPort(packet , inport)
        

        if packet.type == packet.ARP_TYPE:

            ip_of_incoming_packet=packet.payload.protosrc
            if(packet.payload.opcode == arp.REQUEST):
                # Make ARP reply packet 
                print("Arp Request came from {}".format(ip_of_incoming_packet))

                if self.PacketIsFromClient(ip_of_incoming_packet):
                    # if a client ping other host directly then drop packet
                    if(packet.payload.protodst != self.service_ip):
                        log.error("Client cant ping other ip except service ip")
                        return
                    
                    # construct arp reply packet
                    packet_reply= arp()
                    packet_reply.opcode = arp.REPLY
                    packet_reply.hwsrc = self.lb_mac
                    packet_reply.protosrc = self.service_ip
                    packet_reply.hwdst = packet.src
                    packet_reply.protodst = packet.payload.protosrc
                    #send arp reply to client in order to have the mac of service ip
                    self.send_proxied_arp_reply( packet_reply, connection, inport, packet.src)
                    pass
                elif self.PacketIsFromServer(ip_of_incoming_packet):

                    if((packet.payload.protodst in self.user_ip_to_group )or (packet.payload.protodst == self.service_ip)):
                        #construct arp reply packet
                        packet_reply= arp()
                        packet_reply.opcode = arp.REPLY
                        packet_reply.hwsrc = self.lb_mac #load balancer mac
                        packet_reply.protosrc = packet.payload.protodst 
                        packet_reply.hwdst = packet.src #server's mac
                        packet_reply.protodst = packet.payload.protosrc #server's ip
                        
                        #send arp reply to server
                        self.send_proxied_arp_reply(packet_reply,connection,inport,packet.src)
                        return
                    pass
                else:
                    log.error("Packet from unknown ip")
                    return
                
                
                pass
            # Here comes all the arp replies that the service ask for 
            # the ip's of all server in order to know mac and ports of servers          
            elif(packet.payload.opcode==arp.REPLY):
                print("Arp Reply came from {}".format(ip_of_incoming_packet))
                #Connection Up ARP reply came and save the mac-port
                ip = ip_of_incoming_packet #ip from server that replied
                self.servers_ip_to_mac_ports[ip]=(packet.src , inport) #insert mac and port with this ip
                
        elif packet.type == packet.IP_TYPE:

            src_ip = packet.payload.srcip
            if self.PacketIsFromClient(src_ip):
                client_ip = packet.payload.srcip
                print("IP TYPE packet came from client with ip {}".format(client_ip))
                
                # Client cant ping other ip except from service ip whereas server can
                # ping other client but doesn't know that the mac that use is service's mac 
                if(packet.payload.dstip != self.service_ip): #Auto logika den 8a ginei pote alla to vazw
                    log.error("Client cant ping other ip except service ip")
                    return


                if self.ClientHasInstalledRule(client_ip):
                    self.update_lb_mapping(client_ip,buffer_id) # update rule for this client
                    pass
                else:
                    # install rule for this client with random server
                    self.installed_rules_for_clients.add(client_ip)
                    color = self.GetClientsColor(client_ip)
                    server_ip = self.ChooseRandomServer(color)
                    outport = self.servers_ip_to_mac_ports[server_ip][1] #port
                    self.install_flow_rule_client_to_server(connection, outport, client_ip, server_ip , buffer_id)
                    pass
                
                
            elif self.PacketIsFromServer(src_ip):
                server_ip = packet.payload.srcip
                client_ip = packet.payload.dstip
                print("IP TYPE packet came from server with ip {} -> {}".format(server_ip , packet.payload.dstip))

                if(packet.payload.dstip == self.service_ip): #Auto logika den 8a ginei pote alla to vazw
                    log.error("There is no reason a server to ping service ip in order to send IP_TYPE packets")
                    return


                if self.ServerHasInstalledRuleForThisClient(server_ip,client_ip):
                    #update rule of that server and client
                    outport=self.clients_ip_to_mac_ports[client_ip][1]
                    self.connection.send(of.ofp_flow_mod(command=of.ofp_flow_mod_command_rev_map["OFPFC_MODIFY"] ,
                            actions=( of.ofp_action_dl_addr().set_dst(self.clients_ip_to_mac_ports[client_ip][0]),
                            of.ofp_action_nw_addr().set_dst(client_ip) , of.ofp_action_nw_addr().set_src(self.service_ip) ,
                            of.ofp_action_dl_addr().set_src(self.lb_mac),of.ofp_action_output(port=outport)) ,
                            buffer_id=buffer_id , idle_timeout=10 , match=of.ofp_match(dl_type=0x800,nw_src=server_ip,
                            nw_dst=client_ip)))
                    pass
                else:
                    #install rule for that server and client
                    self.installed_rules_for_servers.add((server_ip,client_ip))
                    outport=self.clients_ip_to_mac_ports[client_ip][1]
                    self.install_flow_rule_server_to_client(connection , outport , server_ip , client_ip , buffer_id)
                    pass

                pass
            else:
                log.error("Packet from unknown ip")
                return
            pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        
        pass

    
    def ServerHasInstalledRuleForThisClient(self,server_ip,client_ip):
        return bool((server_ip,client_ip) in self.installed_rules_for_servers)

    def ClientHasInstalledRule(self,client_ip):
        return bool(client_ip in self.installed_rules_for_clients)

    def GetClientsColor(self,ip):
        color = self.user_ip_to_group[ip]
        print("Color is {}".format(color))
        return color

    def PacketIsFromClient(self,requested_ip):
        if(requested_ip in self.user_ip_to_group):
            return True
        return False

    def PacketIsFromServer(self,requested_ip):
        if(requested_ip in self.server_ip_to_group):
            return True
        return False


    def ChooseRandomServer(self,color):
        servers=[IPAddr(i) for i,j in self.server_ip_to_group.items() if j == color]
        ip=random.choice(servers)
        print("Random ip is " , ip)
        return ip

    def CheckIfPacketIsFromClientAndStoreMacAndPort(self,packet,port):
        if(not hasattr(packet.payload,"protosrc")):
            return
        requested_ip = packet.payload.protosrc
        if  requested_ip in self.user_ip_to_group:
            self.clients_ip_to_mac_ports[requested_ip]=(packet.src , port)

        pass





# ----------------------------main------------------------------------

# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
