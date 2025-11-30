import requests
import json

SIEM_APIServer_IP = "http://192.168.1.205"
SIEM_APIServer_PORT = 10900





# query to raw-edr session_timestamp-first_seen
req_path = "/api/solution/siem/event/query/raw-edr/root_session"
parms = {
    "root_session_id" : "3a8796dc83753dd790b85d3f5a4062549ceba1edd3a02d8a7a141e89ca1f656f",
    "size" : 100
}
response = requests.get(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", params=parms )
print( dict( response.json() ) )




"""req_path = "/api/solution/siem/event/query"
DATA = {
    "index_pattern" : "raw-edr*",
    "query_data" : {
        "size": 100,
        "collapse": {
          "field": "header.root_sessionid.keyword"
        },
        "sort": [
          { "header.timestamp_nano_iso8601": "asc" }
        ]
  }
}
response = requests.post(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", json=DATA )
print(response.json())"""

'''req_path = "/api/solution/siem/event/query/timestamp-range/raw-all"
DATA = {
    "start_nano_timestamp" : 1763563078472971800
}
response = requests.get(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", params=DATA )
for k ,v in dict(response.json())["output"]["raw"]["ndr"].items():
  if( k == "total"):
      print((v))'''