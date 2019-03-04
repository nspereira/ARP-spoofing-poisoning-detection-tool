import socket
import struct
import datetime
import subprocess
from colorama import init, Back, Style
import binascii
import os

GW_MAC = '84:94:8c:10:30:d8' # Place your Gateway MAC address 
GW_IP = '192.168.1.1' # As well as your Gateway IP address

now = datetime.datetime.now()

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

init(autoreset=True)

def check_sudo():
    if not os.getuid() == 0:
        sys.exit('Required admin access to run this script!')
        
def check_duplicate():
    with open('blacklist.txt','r+') as f:
        seen = set()
        for line in f:
            line_lower = line.lower()
            if line_lower in seen:
                seen.remove(line_lower)
            else:
                seen.add(line_lower)
                
def arpspoof_detection():
    
    os.system('clear')
    print('\nStarting to sniff ARP packets..')
    
    blacklist = open('blacklist.txt','w')
    
    while True:

        packet = rawSocket.recvfrom(65535)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        ethertype = ethernet_detailed[2]
    
        if (ethertype == '\x08\x06'):
            if (binascii.hexlify(arp_detailed[4]) == '0002') and (binascii.hexlify(arp_detailed[5]) != GW_MAC.replace(':','') and socket.inet_ntoa(arp_detailed[6]) == GW_IP):
                os.system('clear')
                attacker_mac = binascii.hexlify(ethernet_detailed[1])
                victim_mac = binascii.hexlify(ethernet_detailed[0])
                attacker_mac_addr = ':'.join(attacker_mac[i:i+2] for i in range(0,12,2))
                victim_mac_addr = ':'.join(victim_mac[i:i+2] for i in range(0,12,2))
                print(Back.RED + "ALERT: ARP Spoofing detected")
                print ("Attacker MAC: {}".format(attacker_mac_addr))
                f = open("log.txt",'a+')
                f.write('\nDate and time: {} \nAttacker MAC: {} \nVictim MAC: {} \n'.format(now.strftime('%Y-%m-%d %H:%M'),attacker_mac_addr ,victim_mac_addr))
                f.write('*********************************')
                iptablesrule = raw_input('Do you wish to block traffic from MAC adding a rule to iptable?[Y|N]: ')
                if iptablesrule == 'y' or 'Y':
                    subprocess.check_call("/sbin/iptables -A INPUT -m mac --mac-source " + attacker_mac_addr + " -j         DROP",shell=True) 
                    addblacklist = raw_input("Do you wish to add the attackers MAC address to the blacklist?[Y|N]: ")
                    if addblacklist == 'y':
                        blacklist = open('blacklist.txt','a+')
                        check_duplicate()
                        blacklist.write("{}\n".format(attacker_mac_addr))
                        print("The attackers MAC address has been added to the blacklist!")
                        os.system('clear')



if __name__ == '__main__':
    try:
        check_sudo()
        arpspoof_detection()    
    except KeyboardInterrupt: print ('\n exiting...')
    except EOFError: print ('\n exiting...')
    exit(0)
        


