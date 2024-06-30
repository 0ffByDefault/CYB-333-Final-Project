#Import necessary modules for script function
import os
import ipaddress
import ping3
from scapy.all import *

def get_host_info():
    global default_gateway #Define default gateway as a global variable for use in multiple functions
    global dg_mac #Define dg_mac aka default gateway MAC address as a global variable for use in multiple functions
    
    default_gateway = []
    dg_mac = []
    os.system('ipconfig > ipconfig.txt') #Create a file with hte data presented when running ipconfig
    file = open('ipconfig.txt') #Open the file containing ipconfig data
    for line in file: #Loop through the ipconfig.txt file 
        line = line.strip()
        if line.startswith('Default Gateway') == True:
            words = line.split() #Split the line containing the term 'Default Gateway' into words
            try: #This try except statement was created to account for multiple lines containing the Default gateway term which may have the IP in a different index location
                default_gateway.append(words[12]) #Append the 12th word aka the IP address of the default gateway to our default gateway list item
            except:
                continue
    file.close() #Closes the ipconfig.txt file so it can be deleted at the end of the function
    
    os.system('arp -a > arp.txt') #Create another file containing arp table data
    file = open('arp.txt')
    for line in file: #Loop through the arp table data to find the default gateway MAC address
        line = line.strip()
        if line.startswith(str(default_gateway[1])) == True: #Here we use the previously defined IP address of the default gateway to locate its MAC address
            words = line.split() #Split the line into words
            dg_mac.append(words[1]) #Append the MAC address to our dg_mac list item
            break #I only allow this loop to run once because there are multiple entries for the default gateway IP in the ARP table data
    file.close() #Close the file and delete both text files
    os.remove('ipconfig.txt')
    os.remove('arp.txt')



def discovery_scan(subnet): #This function actually works and will return active hosts within a given subnet or IP addresss
    global active_hosts 
    
    active_hosts = [] #Create a list item for our active hosts
    try: #Here we have try and except statements again to determine whether the user entered a IP address or subnet in CIDR notation
        subnet.strip() #Clean extra spaces off the input
        subnet = ipaddress.IPv4Network(subnet) #Attempt to read the input as a subnet
    except:
        try:
            subnet = ipaddress.IPv4Address(subnet) #Attempt to read the input as an individual IPv4 addresss
        except:
            print('Please enter a valid subnet or IP address...') #If neither try statement works exit
            exit()
    
    for ip in subnet: #Loop through the subnet or IP provided by the user
        ip = str(ip) #Turn the IP into a string rather than ipaddress object
        test = ping3.ping(ip) #Send an ICMP echo request to the IP address

        if test != None: #If the ping returns anything but None, which is what happens when the host doesn't respond add it to the list of active hosts
            active_hosts.append(ip)


def spoof_discovery_scan(subnet):
    try:
        subnet.strip() #Clear any extra spaces off the input to prevent errors
        subnet = ipaddress.IPv4Network(subnet) #This is wrapped in a try statement because if the subnet is not a valid subnet in CIDR notation we will move on to the next try statement
    except:
        try:
            subnet = ipaddress.IPv4Address(subnet) #This try statement checks if the user has entered an IP instead of a subnet which would also be valid input
        except:
            print('Please enter a valid subnet or IP address...') #If neither try statement works we say so and exit the program for simplicity
            exit()
    for ip in subnet: #Here we are looping through the subnet which, thanks to the ipaddress module, is read like a list of IP addresses or just one IP address depending on the user input
        str(ip) #Turning the ipaddress into a string so it is compatible with Scapy
        icmp = Ether(src = str(dg_mac[0]))/IP(dst=str(ip),src=str(default_gateway[1]))/ICMP() #Create the spoofed packet with the MAC address and IP address of the default gateway
        resp = sniff(filter = f'src host {ip} and dst host {str(default_gateway[0])}') #Set a filter to sniff for the responses originating from the target hosts and being sent to the default gateway
        print(resp) #Show the responses so we can tell which hosts are responding


    


get_host_info() #Gatheer the ip address and MAC address of default gateway
discovery_scan('192.168.0.0/29') #Send spoofed packets and monitor the hosts response