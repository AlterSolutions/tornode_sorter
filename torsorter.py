import requests

# All definition regardiong node objects : https://metrics.torproject.org/onionoo.html

url = "https://onionoo.torproject.org/details?limit=100000"

response = requests.get(url)

response_json = dict(response.json())
#print(response_json)

relay_list = response_json["relays"]


for node in relay_list:

    if "Guard" in node["flags"]:
        try:
            if node["guard_probability"] != 0:
                for ip in node["or_addresses"]:
                    a = 1

                    print(ip + "  -  " + str(node["flags"]))
                    #print(node["guard_probability"] )

        # some nodes doesnt have "guard_probability object since they have not been seen the last hour
        except:
            exit
