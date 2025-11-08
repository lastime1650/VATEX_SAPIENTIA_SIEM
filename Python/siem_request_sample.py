import requests
import json

SIEM_APIServer_IP = "http://192.168.1.205"
SIEM_APIServer_PORT = 10900


req_path = "/api/solution/siem/push/event/security-threat"
Data = \
{
  "platform": "xdr",
  "timestamp_nano": 1730105630112233445,
  "event_id": "xdr-evt-abcdef12-3456-7890-1234-567890abcdef",
  "severity": "medium",
  "topic": "Anomalous Data Exfiltration Detected",
  "description": "AI model detected an unusual volume of data being uploaded from a database server (10.0.5.20) to an external cloud storage provider outside of normal business hours. This activity deviates significantly from the established baseline.",
  "response_description": "Review the uploaded data to determine if it contains sensitive information. Verify with the server administrator if this activity was authorized.",
  "detected_method": "ai"
}
response = requests.post(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", data=json.dumps(Data).encode() )
print( dict( response.json() ) )