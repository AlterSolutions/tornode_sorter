import requests

# All definition regardiong node objects : https://metrics.torproject.org/onionoo.html

url = "https://onionoo.torproject.org/details?limit=100000"

response = requests.get(url)

response_json = dict(response.json())
#print(response_json)

relay_list = response_json["relays"]

# Initialisation of the global lists
guard_list = {}

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
                    guard_list.setdefault(port,[]).append(ip)


                    #print(ip + "  -  " + str(node["flags"]))
                    #print(node["guard_probability"] )

        # some nodes doesnt have "guard_probability object since they have not been seen the last hour
        except:
            exit


#print(guard_list[21])
#print(guard_list.keys())

# Creation of the files for guard nodes per ports
for port in guard_list.keys():
    filename = "tor_guards_" + str(port)
    file = open(filename,'w')
    for ip in guard_list[port]:
        file.writelines(ip + '\n')

