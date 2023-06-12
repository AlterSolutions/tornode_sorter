#!/usr/bin/env python3
import requests
import os


####################################
#### GLOBAL VARIABLE DEFINITION ####
####################################

# All definition regardiong node objects : https://metrics.torproject.org/onionoo.html
url = "https://onionoo.torproject.org"
args = "details?limit=100000"
full_url = url + '/' + args

output_directory = "/srv/tornodes_lists/"
guards_subdirectory = "guards/"
exit_subdirectory = "exit/"

raw_response = requests.get(full_url)
response_json = dict(raw_response.json())

relay_list = response_json["relays"]

def extract_ip_port(ip_port_string: str) -> dict:
    """
    Parse a string representing an IP:PORT couple
    detect if it is IPV4 or IPV6 and split it in the right way.
    Return an IP Port dictionnary :
        {"IP" : "<IP>"; "PORT": int(<port>)}
    """
    ip_port_dict = dict()

    if ip_port_string[0] != '[': # if IPv4
        ip = ip_port_string.split(':')[0]
        port = int(ip_port_string.split(':')[1])
    else: # if IP6v
        ip = ip_port_string[1:].split(']')[0]
        port = int(ip_port_string[1:].split(']')[1][1:])

    ip_port_dict["IP"] = ip
    ip_port_dict["PORT"] = port

    return ip_port_dict


def get_all_guards_ips(nodes: list) -> set:
    """
    Create a set of all probable guard of the tor network
    Entry : list of TOR nodes (dict)
    Return : Set of IPs
    """
    all_guard_ip = set()
    for node in nodes:
        if "Guard" in node["flags"]:
            try:
                if node["guard_probability"] != 0:
                    for ip_port in node["or_addresses"]:
                        ip = extract_ip_port(ip_port)["IP"]
                        all_guard_ip.add(ip)
            # some nodes doesnt have "guard_probability object since they have not been seen the last hour
            except:
                exit
    return all_guard_ip



def get_guard_per_port(nodes: list) -> dict:
    """
    Parse the list of nodes given in entry
    Return a dictionnary of all possible entry ports with their respective IPs :
        Format : { port : [<list of IPs>], ...}

    """
    guard_list_ports = {}

   # print(nodes)

    for node in nodes:
        if "Guard" in node["flags"]:
            try:
                if node["guard_probability"] != 0:
                    for ip_port in node["or_addresses"]:
                        ip = extract_ip_port(ip_port)["IP"]
                        port = extract_ip_port(ip_port)["PORT"]
                        
                        guard_list_ports.setdefault(port,set()).add(ip)
            # some nodes doesnt have "guard_probability" object since they have not been seen the last hour
            except:
                exit
    return guard_list_ports



#print(get_guard_per_port(relay_list))
#print(get_all_guards_ip(relay_list))

#Creation of the list of all guard nodes

def write_file_all_guards_ips(all_guards_ips: set) -> None:
    """
    Write all guards IPs in a file
    Entry : set of Ips
    """
    guards_directory = output_directory + guards_subdirectory 
    # check if the output_directory exists
    if not os.path.exists(guards_directory):
        os.makedirs(guards_directory)

    filename = "all_guards_ips"
    full_path = guards_directory +  filename

    file = open(full_path,'w')
    for ip in all_guards_ips:
        file.write(ip + "\n")
    file.close()

def write_file_guards_per_port(guard_list_port: dict) -> None:
    """
    Create one file per port used as entry guard
    for each of these files, write the list of related IPs
    """
   
    guards_port_directory = output_directory + guards_subdirectory + "ports/"

    # check if the output_directory exists
    if not os.path.exists(guards_port_directory):
        os.makedirs(guards_port_directory)

    for port in guard_list_port.keys():
        filename = "tor_guards_" + str(port)
        full_path = guards_port_directory + filename
        file = open(full_path,'w')
        for ip in guard_list_port[port]:
            file.write(ip + '\n')
        file.close()

#1- write the list of all guards
write_file_all_guards_ips(get_all_guards_ips(relay_list))

#2 write all the files with list of guards per ip
write_file_guards_per_port(get_guard_per_port(relay_list))

