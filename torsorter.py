import requests

# All definition regardiong node objects : https://metrics.torproject.org/onionoo.html

url = "https://onionoo.torproject.org/details?limit=100000"

response = requests.get(url)

response_json = dict(response.json())
#print(response_json)

relay_list = response_json["relays"]

# Initialisation of the global lists
guard_list_ports = {} # dictionary of all guards, ordered by listening ports
guard_set = set() # set of IP of all guards


for node in relay_list:


    if "Guard" in node["flags"]:
        try:
            if node["guard_probability"] != 0:
                
                for ip_port in node["or_addresses"]:
                    #If IPv4
                    if ip_port[0] != '[':
                        ip = ip_port.split(':')[0]
                        port = int(ip_port.split(':')[1])
                    else: # if IPv4
                        ip = ip_port[1:].split(']')[0]
                        port = int(ip_port[1:].split(']')[1][1:])
                    #guard_list.setdefault(port,()).append(ip)
                    guard_list_ports.setdefault(port,set()).add(ip)
                    guard_set.add(ip)

        # some nodes doesnt have "guard_probability object since they have not been seen the last hour
        except:
            exit

#Creation of the list of all guard nodes
filename = "./guards/all_guards_ips"
file = open(filename,'w')
for ip in guard_set:
    file.write(ip + '\n')

file.close()


# Creation of the files for guard nodes per ports
for port in guard_list_ports.keys():
    filename = "./guards/ports/tor_guards_" + str(port)
    file = open(filename,'w')
    for ip in guard_list_ports[port]:
        file.write(ip + '\n')
    file.close()
