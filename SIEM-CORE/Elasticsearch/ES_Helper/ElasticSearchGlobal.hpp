#ifndef ES_GLOBAL_HPP
#define ES_GLOBAL_HPP

#include "../../../Util/util.hpp"

namespace SIEM
{
    namespace Server
    {
        namespace Elasticsearch
        {
            namespace Global
            {
                namespace Index_Templates
                {
                    const std::string raw_ndr_index_template_name = "raw-ndr-index-template";
                    const json raw_ndr_index_template = {
                        {"index_patterns", json::array({"raw-ndr-*"}) },
                        {"priority", 500},
                        {"template", {
                            {"settings", {
                                {"number_of_shards",   4},
                                {"number_of_replicas",   1}
                            }},
                            {"mappings", {
                                {"properties", {
                                    // IAM
                                    { "IAM", {
                                        {"properties", {
                                            { "ticket" , { { "type", "keyword" } } },
                                            { "username" , { { "type", "keyword" } } }, // 해당 트래픽과 연관된 유저명
                                            {"ipv4", {{"type", "ip"}}},              // 해당 트래픽에 포함된 유저의 IPV4
                                            {"agent_id", {{"type", "keyword"}}}         // 해당 트래픽에 포함된 유저의 에이전트ID
                                        } }
                                    } },
                                    
                                    {"sensor_id", { {"type", "keyword"} }},
                                    {"flow_session_id", { {"type", "keyword"} }},
                                    {"session_first_seen_nano", { {"type", "long"} }},
                                    {"session_last_seen_nano", { {"type", "long"} }},
                                    {"event_count", { {"type", "long"} }},
                                    {"events", { 
                                        {"type", "object"},
                                        {"properties", {
                                            // 공통
                                            { "timestamp_nano", { { "type", "long" } } },

                                            // < 기본 패킷 메타데이터 >
                                            { "src_ip", { { "type", "ip" } } },
                                            { "src_port", { { "type", "integer" } } },
                                            { "dst_ip", { { "type", "ip" } } },
                                            { "dst_port", { { "type", "integer" } } },
                                            { "direction", { { "type", "keyword" } } },
                                            { "protocol", { { "type", "keyword" } } },
                                            { "interfacename", { { "type", "keyword" } } },
                                            // < 규칙 기반 flow 시나리오 >
                                            { "rule", { 
                                                { "properties", {
                                                    { "id", { { "type", "keyword" } } },
                                                    { "description", { { "type", "text" } } },
                                                    { "severity", { { "type", "keyword" } } },
                                                    { "stage_node_location_index", { { "type", "long" } } }, // main.cpp 주석에는 integer로 되어있으나 long이 더 유연합니다.
                                                    { "stage_index_name", { { "type", "keyword" } } },
                                                    { "stage_action", { { "type", "keyword" } } },
                                                    { "stage_action_message", { { "type", "text" } } }
                                                } } 
                                            } }
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    };

                    const std::string raw_edr_index_template_name = "raw-edr-index-template";
                    const json raw_edr_index_template = {
                        {"index_patterns", json::array({"raw-edr-*"}) },
                        {"priority", 500},
                        {"template", {
                            {"settings", {
                                {"number_of_shards", 4},
                                {"number_of_replicas", 1}
                            }},
                            {"mappings", {
                                {"properties", {
                                    // IAM
                                    { "IAM", {
                                        {"properties", {
                                            { "ticket" , { { "type", "keyword" } } },
                                            { "username" , { { "type", "keyword" } } }, // 해당 트래픽과 연관된 유저명
                                            {"ipv4", {{"type", "ip"}}},              // 해당 트래픽에 포함된 유저의 IPV4
                                            {"agent_id", {{"type", "keyword"}}}         // 해당 트래픽에 포함된 유저의 에이전트ID
                                        } }
                                    } },

                                    {"agent_id", { {"type", "keyword"} }},
                                    {"os_platform", { {"type", "keyword"} }},
                                    {"os_version", { {"type", "keyword"} }},
                                    {"event_count", { {"type", "long"} }},
                                    {"events", { 
                                        {"type", "object"},
                                        {"properties", {
                                            // 공통
                                            { "timestamp_nano", { { "type", "long" } } },
                                            { "self_session_id", { { "type", "keyword" } } },
                                            { "parent_session_id", { { "type", "keyword" } } },
                                            { "root_session_id", { { "type", "keyword" } } },
                                            { "pid", { { "type", "long" } } },

                                            // < 프로세스 생성 이벤트 >
                                            { "processcreation", {
                                                { "properties", {
                                                    { "exe_path", { { "type", "keyword" } } },
                                                    { "exe_size", { { "type", "long" } } },
                                                    { "exe_sha256", { { "type", "keyword" } } },
                                                    { "commandline", { { "type", "text" } } },
                                                    { "ppid", { { "type", "long" } } },
                                                    { "parent_exe_path", { { "type", "keyword" } } },
                                                    { "parent_exe_size", { { "type", "long" } } },
                                                    { "parent_exe_sha256", { { "type", "keyword" } } },
                                                    { "user", {
                                                        { "properties", {
                                                            { "username", { { "type", "keyword" } } },
                                                            { "windows_sid", { { "type", "keyword" } } },
                                                            { "linux_uid", { { "type", "keyword" } } }
                                                        }}
                                                    }}
                                                }}
                                            }},

                                            // < 프로세스 종료 이벤트 >
                                            { "processterminate", {
                                                { "properties", {
                                                    { "ppid", { { "type", "keyword" } } }
                                                }}
                                            }},

                                            // < 파일시스템 이벤트 >
                                            { "filesystem", {
                                                { "properties", {
                                                    { "action", { { "type", "keyword" } } },
                                                    { "filepath", { { "type", "keyword" } } },
                                                    { "filesize", { { "type", "long" } } },
                                                    { "filesha256", { { "type", "keyword" } } }
                                                }}
                                            }},

                                            // < 네트워크 이벤트 >
                                            { "network", {
                                                { "properties", {
                                                    { "protocol", { { "type", "keyword" } } },
                                                    { "packetsize", { { "type", "integer" } } },
                                                    { "src_ip", { { "type", "ip" } } },
                                                    { "src_port", { { "type", "integer" } } },
                                                    { "dst_ip", { { "type", "ip" } } },
                                                    { "dst_port", { { "type", "integer" } } },
                                                    { "direction", { { "type", "keyword" } } },
                                                    { "network_session_id", { { "type", "keyword" } } },
                                                    { "network_session_first_seen", { { "type", "long" } } },
                                                    { "network_session_last_seen", { { "type", "long" } } }
                                                }}
                                            }},

                                            // < API후킹 이벤트 >
                                            { "apihook", {
                                                { "properties", json::object() }
                                            }},

                                            // < Windows 이미지 로드 이벤트 >
                                            { "imageload", {
                                                { "properties", {
                                                    { "imagepath", { { "type", "keyword" } } },
                                                    { "imagesize", { { "type", "long" } } },
                                                    { "imagesha256", { { "type", "keyword" } } }
                                                }}
                                            }},

                                            // < Windows 프로세스 접근 이벤트 >
                                            { "processaccess", {
                                                { "properties", {
                                                    { "handletype", { { "type", "keyword" } } },
                                                    { "target_exe_path", { { "type", "keyword" } } },
                                                    { "target_pid", { { "type", "keyword" } } },
                                                    { "desiredaccesses", { { "type", "keyword" } } } // 배열 입력 가능
                                                }}
                                            }},

                                            // < Windows 레지스트리 이벤트 >
                                            { "registry", {
                                                { "properties", {
                                                    { "keyclass", { { "type", "keyword" } } },
                                                    { "name", { { "type", "keyword" } } }
                                                }}
                                            }},

                                            // < Windows ETW 이벤트 >
                                            { "etw", {
                                                { "properties", {}}
                                            }},

                                            // < 규칙기반 정보 >
                                            { "rule", {
                                                { "properties", {
                                                    { "id", { { "type", "keyword" } } },
                                                    { "name", { { "type", "text" } } },
                                                    { "description", { { "type", "text" } } },
                                                    { "severity", { { "type", "keyword" } } },
                                                    { "mitre_attack", {
                                                        { "type", "object" },
                                                        { "properties", {
                                                            { "tactic", { { "type", "keyword" } } },
                                                            { "technique_id", { { "type", "keyword" } } },
                                                            { "subtechnique_id", { { "type", "keyword" } } },
                                                            { "data_sources", { { "type", "keyword" } } }
                                                        }}
                                                    }},
                                                    { "platform", { { "type", "keyword" } } },
                                                    { "stage_id", { { "type", "keyword" } } },
                                                    { "action", { { "type", "keyword" } } },
                                                    { "action_message", { { "type", "keyword" } } },
                                                    { "operational_usage", { { "type", "text" } } },
                                                    { "false_positive", { { "type", "text" } } }
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    };

                    const std::string security_threat_index_template_name = "security-threat-index-template";
                    const json security_threat_index_template = {
                        {"index_patterns", json::array({"security-threat-*"}) },
                        {"priority", 300},
                        {"template", {
                            {"settings", {
                                {"number_of_shards", 4},
                                {"number_of_replicas", 1}
                            }},
                            {"mappings", {
                                {"properties", {
                                    { "platform", { { "type", "keyword" } } },              // 이벤트 전송한 플랫폼 (ndr, xdr, edr, soar 등)
                                    { "timestamp_nano", { { "type", "long" } } },           // 타임스탬프 (나노초 단위)
                                    { "event_id", { { "type", "keyword" } } },              // 이벤트 식별자
                                    { "severity", { { "type", "keyword" } } },              // 심각도
                                    { "topic", { { "type", "keyword" } } },                 // 위협 주제
                                    { "description", { { "type", "text" } } },              // 위협 기술 설명
                                    { "response_description", { { "type", "text" } } },     // 대응 및 차단 방법
                                    { "detected_method", { { "type", "keyword" } } }        // 탐지 방식 (signature / ai)
                                }}
                            }}
                        }}
                    };


                }
                namespace Helper
                {
                    // raw-ndr json text to json
                    
                }
            }
        }
    }
}

#endif