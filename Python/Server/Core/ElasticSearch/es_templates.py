# es_templates.py
# 엘라스틱서치 인덱스 템플릿 선언들

# raw-ndr 인덱스 템플릿
RAW_NDR_INDEX_TEMPLATE_NAME = "raw-ndr-index-template"
RAW_NDR_INDEX_TEMPLATE = {
    "index_patterns": ["raw-ndr-*"],
    "priority": 500,
    "template": {
        "settings": {
            "number_of_shards": 4,
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "IAM": {
                    "properties": {
                        "ticket": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "ipv4": {"type": "ip"},
                        "agent_id": {"type": "keyword"}
                    }
                },
                "sensor_id": {"type": "keyword"},
                "flow_session_id": {"type": "keyword"},
                
                "timestamp": {
                    "properties": {
                        "first_seen": {"type":"long"},
                        "last_seen": {"type":"long"},
                        "first_seen_iso8601": {"type":"date_nanos"},
                        "last_seen_iso8601": {"type":"date_nanos"}
                    }
                },
                
                "event_count": {"type": "long"},
                "events": {
                    "type": "nested", # 
                    "properties": {
                        "timestamp_nano_iso8601": {"type": "date_nanos"},
                        "timestamp_nano": {"type": "long"},
                        "src_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_ip": {"type": "ip"},
                        "dst_port": {"type": "integer"},
                        "direction": {"type": "keyword"},
                        "protocol": {"type": "keyword"},
                        "interfacename": {"type": "keyword"},
                        "rule": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "description": {"type": "text"},
                                "severity": {"type": "keyword"},
                                "stage_node_location_index": {"type": "long"},
                                "stage_index_name": {"type": "keyword"},
                                "stage_action": {"type": "keyword"},
                                "stage_action_message": {"type": "text"}
                            }
                        }
                    }
                }
            }
        }
    }
}

# raw-edr 인덱스 템플릿
RAW_EDR_INDEX_TEMPLATE_NAME = "raw-edr-index-template"
"""RAW_EDR_INDEX_TEMPLATE = {
    "index_patterns": ["raw-edr-*"],
    "priority": 500,
    "template": {
        "settings": {
            "number_of_shards": 4,
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "IAM": {
                    "properties": {
                        "ticket": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "ipv4": {"type": "ip"},
                        "agent_id": {"type": "keyword"}
                    }
                },
                "agent_id": {"type": "keyword"},
                "os_platform": {"type": "keyword"},
                "os_version": {"type": "keyword"},
                "event_count": {"type": "long"},
                "events": {
                    "type": "nested",
                    "properties": {
                        "timestamp_nano_iso8601": {"type": "date_nanos"},
                        "timestamp_nano": {"type": "long"},
                        "self_session_id": {"type": "keyword"},
                        "parent_session_id": {"type": "keyword"},
                        "root_session_id": {"type": "keyword"},
                        "pid": {"type": "long"},
                        "processcreation": {
                            "properties": {
                                "exe_path": {"type": "keyword"},
                                "exe_size": {"type": "long"},
                                "exe_sha256": {"type": "keyword"},
                                "commandline": {"type": "text"},
                                "ppid": {"type": "long"},
                                "parent_exe_path": {"type": "keyword"},
                                "parent_exe_size": {"type": "long"},
                                "parent_exe_sha256": {"type": "keyword"},
                                "user": {
                                    "properties": {
                                        "username": {"type": "keyword"},
                                        "windows_sid": {"type": "keyword"},
                                        "linux_uid": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "processterminate": {"properties": {"ppid": {"type": "keyword"}}},
                        "filesystem": {
                            "properties": {
                                "action": {"type": "keyword"},
                                "filepath": {"type": "keyword"},
                                "filesize": {"type": "long"},
                                "filesha256": {"type": "keyword"}
                            }
                        },
                        "network": {
                            "properties": {
                                "protocol": {"type": "keyword"},
                                "packetsize": {"type": "integer"},
                                "src_ip": {"type": "ip"},
                                "src_port": {"type": "integer"},
                                "dst_ip": {"type": "ip"},
                                "dst_port": {"type": "integer"},
                                "direction": {"type": "keyword"},
                                "network_session_id": {"type": "keyword"},
                                "network_session_first_seen": {"type": "long"},
                                "network_session_last_seen": {"type": "long"}
                            }
                        },
                        "apihook": {"properties": {}},
                        "imageload": {
                            "properties": {
                                "imagepath": {"type": "keyword"},
                                "imagesize": {"type": "long"},
                                "imagesha256": {"type": "keyword"}
                            }
                        },
                        "processaccess": {
                            "properties": {
                                "handletype": {"type": "keyword"},
                                "target_exe_path": {"type": "keyword"},
                                "target_pid": {"type": "keyword"},
                                "desiredaccesses": {"type": "keyword"}
                            }
                        },
                        "registry": {
                            "properties": {
                                "keyclass": {"type": "keyword"},
                                "name": {"type": "keyword"}
                            }
                        },
                        "etw": {
                            "properties": {
                                "event_flags": {"type": "integer"},
                                "event_id": {"type": "integer"},
                                "event_name": {"type": "keyword"},
                                "event_version": {"type": "integer"},
                                "fields": {
                                    "properties": {}
                                }
                            }
                        },
                        "rule": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "text"},
                                "description": {"type": "text"},
                                "severity": {"type": "keyword"},
                                "mitre_attack": {
                                    "properties": {
                                        "tactic": {"type": "keyword"},
                                        "technique_id": {"type": "keyword"},
                                        "subtechnique_id": {"type": "keyword"},
                                        "data_sources": {"type": "keyword"}
                                    }
                                },
                                "platform": {"type": "keyword"},
                                "stage_id": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "action_message": {"type": "keyword"},
                                "operational_usage": {"type": "text"},
                                "false_positive": {"type": "text"}
                            }
                        }
                    }
                }
            }
        }
    }
}"""
RAW_EDR_INDEX_TEMPLATE = {
    "index_patterns": ["raw-edr-*"],
    "priority": 500,
    "template": {
        "settings": {
            "number_of_shards": 4,
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "IAM": {
                    "properties": {
                        "ticket": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "ipv4": {"type": "ip"},
                        "agent_id": {"type": "keyword"}
                    }
                },
                "agent_id": {"type": "keyword"},
                "os_platform": {"type": "keyword"},
                "os_version": {"type": "keyword"},

                "root_process_sha256": { "type": "keyword" },
                "is_alive": { "type": "boolean" },
                "is_placeholder": { "type": "boolean" },
                "nodeMaxDepth": { "type": "long" },
                "child_count": { "type": "long" },
                "event_count": {"type": "long"},
                "session": {
                  "properties": {
                    "SessionID": { "type": "keyword" },
                    "Root_SessionID": { "type": "keyword" },
                    "Parent_SessionID": { "type": "keyword" }
                  }
                },
                "shared_tree_timestamp": {
                  "properties": {
                    "first_seen": { "type": "long" },
                    "last_seen": { "type": "long" }
                  }
                },
                "rules": {
                    "type": "nested",
                    "properties": {
                        "id": {"type": "keyword"},
                        "name": {"type": "text"},
                        "description": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "mitreattacks": {
                            "type": "nested",
                            "properties": {
                                "tactic_id": {"type": "keyword"},
                                "technique_id": {"type": "keyword"},
                                "subtechnique_id": {"type": "keyword"},
                                "data_sources": {"type": "keyword"}
                            }
                        },
                        "platforms": {"type": "keyword"},
                        "operational_usage": {"type": "text"},
                        "false_positive": {"type": "text"}
                    }
                },
                "intelligences": {
                    "type": "object",
                    "enabled": False
                },
                "events": {
                    "type": "nested",
                    "properties": {
                        "header": {
                            "properties": {
                                "agentid": { "type": "keyword" },
                                "sessionid": { "type": "keyword" },
                                "root_sessionid": { "type": "keyword" },
                                "parent_sessionid": { "type": "keyword" },
                                "nano_timestamp": { "type": "long" },
                                "timestamp_nano_iso8601": {"type": "date_nanos"},
                                "os": {
                                    "properties": {
                                        "type": { "type": "keyword" },
                                        "version": { "type": "keyword" }
                                    }
                                }
                            }
                        },
                        "body": {
                            "properties": {
                                "process": {
                                    "properties": {
                                        "action": {"type": "keyword"},
                                        "exe_path": {"type": "keyword"},
                                        "exe_size": {"type": "long"},
                                        "exe_sha256": {"type": "keyword"},
                                        "commandline": {"type": "text"},
                                        "ppid": {"type": "long"},
                                        "parent_exe_path": {"type": "keyword"},
                                        "parent_exe_size": {"type": "long"},
                                        "parent_exe_sha256": {"type": "keyword"},
                                        "user": {
                                            "properties": {
                                                "username": {"type": "keyword"},
                                                "sid": {"type": "keyword"}
                                            }
                                        }
                                    }
                                },
                                "filesystem": {
                                    "properties": {
                                        "action": {"type": "keyword"},
                                        "filepath": {"type": "keyword"},
                                        "filesize": {"type": "long"},
                                        "filesha256": {"type": "keyword"}
                                    }
                                },
                                "network": {
                                    "properties": {
                                        "protocol": {"type": "keyword"},
                                        "packetsize": {"type": "integer"},
                                        "sourceip": {"type": "ip"},
                                        "sourceport": {"type": "integer"},
                                        "destinationip": {"type": "ip"},
                                        "destinationport": {"type": "integer"},
                                        "direction": {"type": "keyword"},
                                        "session": {
                                            "properties": {
                                                "sessionid": { "type": "keyword" },
                                                "first_seen": { "type": "long" },
                                                "last_seen": { "type": "long" }
                                            }
                                        }
                                    }
                                },
                                "imageload": {
                                    "properties": {
                                        "filepath": {"type": "keyword"},
                                        "filesize": {"type": "long"},
                                        "filesha256": {"type": "keyword"}
                                    }
                                },
                                "processaccess": {
                                    "properties": {
                                        "handletype": {"type": "keyword"},
                                        "filepath": {"type": "keyword"},
                                        "target_pid": {"type": "long"},
                                        "desiredaccesses": {"type": "keyword"}
                                    }
                                },
                                "registry": {
                                    "properties": {
                                        "keyclass": {"type": "keyword"},
                                        "name": {"type": "keyword"}
                                    }
                                },
                                "etw": {
                                    "properties": {
                                        "event_flags": {"type": "integer"},
                                        "event_id": {"type": "integer"},
                                        "event_name": {"type": "keyword"},
                                        "event_version": {"type": "integer"},
                                        "fields": {
                                            "properties": {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# security-threat 인덱스 템플릿
RAW_XDR_INDEX_TEMPLATE_NAME = "raw-xdr-index-template"
RAW_XDR_INDEX_TEMPLATE = {
    "index_patterns": ["raw-xdr-*"],
    "priority": 300,
    "template": {
        "settings": {
            "number_of_shards": 4,
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "header": {
                    "properties": {}
                },
                "body": {
                    "properties": {}
                }
            }
        }
    }
}
                

# security-threat 인덱스 템플릿
SECURITY_THREAT_INDEX_TEMPLATE_NAME = "security-threat-index-template"
SECURITY_THREAT_INDEX_TEMPLATE = {
    "index_patterns": ["security-threat-*"],
    "priority": 300,
    "template": {
        "settings": {
            "number_of_shards": 4,
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "timestamp_nano_iso8601": {"type": "date_nanos"},
                "platform": {"type": "keyword"},
                "timestamp_nano": {"type": "long"},
                "event_id": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "topic": {"type": "keyword"},
                "description": {"type": "text"},
                "response_description": {"type": "text"},
                "detected_method": {"type": "keyword"}
            }
        }
    }
}

