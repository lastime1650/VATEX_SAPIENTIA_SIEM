#include "SIEM-CORE/SIEM_CORE_Server.hpp"

bool set_fail_response(std::string reason, httplib::Response& res)
{
    json body = {
        {"status", false},
        {"fail_reason", reason}
    };

    res.set_content(body.dump(), "application/json");

    return true;
}
bool set_success_response(json output, httplib::Response& res)
{
    json body = {
        {"status", true},
        {"output", output}
    };

    res.set_content(body.dump(), "application/json");

    return true;
}

int main()
{
    /*
        SIEM CORE 개발
        * SIEM내부 이벤트 처리 엔진은 ElasticSearch 이며, GUI는 Kibana
    */
    /*
        < Index Templates >
        < 대표 >
        1. raw      (각 솔루션에서 별도로 저장 (세션으로 저장된 정보)하는 순수한 이벤트로그 정보)
        2. security   ( 각 솔루션에서 SIEM에서 알맞는 정규화된 필드로 구성된 위협-보안 이벤트로그 정보 )

        < 상세 >
        1. raw
            -> 1.A raw-ndr
            -> 1.B raw-edr
            -> 1.C raw-xdr
        2. threat
            -> 2.A security-threat (보편적)
            -> 2.B security-threat-ai (AI예측을 통한 스코어 포함 결정?????) <이건 무시해도됨>

        < 상세 - 템플릿 >
        1. raw
            -> 1.A raw-ndr
                -> // 한 Document당 세션 전체를 전달해야함. *그렇다고 해서 세션 전체를 그대로 크게 전달하면 무리가 갈 수 있으니, 요청부에서 최대한 요약해서 다음과 같은 템플릿에 부합할 수 있도록 요약처리해야함
                {
                    "template" : {
                        "settings": {
                            "number_of_shards":   4,
			                "number_of_replicas": 1,
                        },
                        "mappings": {
                            "properties" : {
                                "sensor_id": { "type": "keyword" },             // Sensor 아이디
                                "flow_session_id": { "type": "keyword" },               // 네트워크 세션
                                "session_first_seen_nano": { "type": "long" },       // 세션 추적 시작일자
                                "session_last_seen_nano": { "type": "long" },        // 세션 추적 최근일자
                                "event_count": {"type":"long"},                      // 이벤트 개수 (original) * events 배열오브젝트 개수와 동일하지 않아도됨 그냥 그대로 모은 개수를 지정하라.
                                "events": {
                                    "type": "object",                                   // 다음 properties는 배열임 ㅇ
                                    "properties" : {
                                        // 공통
                                        "timestamp_nano" : { "type": "long" },

                                        
                                        // < 기본 패킷 메타데이터 >
                                        "src_ip": { "type": "ip" },
                                        "src_port": {"type": "integer"},

                                        "dst_ip": { "type": "ip" },
                                        "dst_port": {"type": "integer"},
                                        
                                        "direction": {"type":"keyword"},
                                        "protocol": {"type":"keyword"},
                                        "interfacename": {"type":"keyword"},

                                        // < 규칙기반 정보 >
                                        "rule" : {
                                            "properties" : {
                                                "id": {"type":"keyword"},
                                                "description": {"type":"text"},
                                                "severity": {"type":"keyword"},
                                                "stage_node_location_index": {"type":"integer"},
                                                "stage_index_name": {"type":"keyword"},
                                                "stage_action": {"type":"keyword"},
                                                "stage_action_message": {"type":"text"}
                                            }
                                        }
                                        

                                    }
                                }
                            }
                        }
                    }
                }
            -> 1.B raw-edr
                -> 한 프로세스에서 발생한 전체 Tree 흐름
                {
                    "template" : {
                        "settings": {
                            "number_of_shards":   4,
			                "number_of_replicas": 1,
                        },
                        "mappings": {
                            "properties" : {
                                "agent_id": { "type": "keyword" },             // Agent 아이디
                                "os_platform" : {"type": "keyword"},
                                "os_version" : {"type":"keyword"},
                                "event_count": {"type":"long"},                      // 이벤트 개수 (original) * events 배열오브젝트 개수와 동일하지 않아도됨 그냥 그대로 모은 개수를 지정하라.
                                "events": {
                                    "type": "object",                                   // 다음 properties는 배열임 ㅇ
                                    "properties" : {
                                        // 공통
                                        "timestamp_nano" : { "type": "long" },
                                        "self_session_id": {"type": "keyword"},
                                        "parent_session_id": {"type": "keyword"},
                                        "root_session_id": {"type": "keyword"},
                                        "pid": {"type": "long"},

                                        
                                        // < 프로세스 생성 이벤트 >
                                        "processcreation": {
                                            "properties" : {
                                                "exe_path": {"type": "keyword"},
                                                "exe_size": {"type": "long"},
                                                "exe_sha256": {"type": "keyword"},
                                                "commandline": {"type": "text"},
                                                "ppid": {"type": "long"},
                                                "parent_exe_path": {"type": "keyword"},
                                                "parent_exe_size": {"type": "long"},
                                                "parent_exe_sha256": {"type": "keyword"},

                                                "user": {
                                                    "properties" : {
                                                        "username": {"type": "keyword"},
                                                        "windows_sid" : {"type": "keyword"},
                                                        "linux_uid" : {"type": "keyword"},
                                                    }
                                                }
                                                
                                                
                                            }
                                        },
                                        // < 프로세스 종료 이벤트 >
                                        "processterminate": {
                                            "properties" : {
                                                "ppid": {"type": "keyword"},
                                            }
                                        },
                                        // < 파일시스템 이벤트 >
                                        "filesystem": {
                                            "properties" : {
                                                "action": {"type": "keyword"},
                                                "filepath": {"type": "keyword"},
                                                "filesize": {"type": "long"},
                                                "filesha256": {"type": "keyword"}
                                            }
                                        },
                                        // < 네트워크 이벤트 >
                                        "network": {
                                            "properties" : {
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
                                        // < API후킹 이벤트 > -> none
                                        "apihook": {
                                            "properties" : {}
                                        },

                                        // < Windows-이미지로드 이벤트 >
                                        "windows_imageload": {
                                            "properties" : {
                                                "imagepath": {"type": "keyword"},
                                                "imagesize": {"type": "long"},
                                                "imagesha256": {"type": "keyword"}
                                            }
                                        },
                                        // < Windows-프로세스접근 이벤트 >
                                        "windows_processaccess": {
                                            "properties" : {
                                                "handletype": {"type": "keyword"},
                                                "target_exe_path": {"type": "keyword"},
                                                "target_pid": {"type": "keyword"},
                                                "desiredaccesses": {"type": "keyword"} // 배열로 전달되지만, 내부에서 배열처리됨
                                            }
                                        },
                                        // < Windows-레지스트리 이벤트 >
                                        "windows_registry": {
                                            "properties" : {
                                                "keyclass": {"type": "keyword"},
                                                "name": {"type": "keyword"},
                                            }
                                        }
                                        

                                        // < 규칙기반 정보 >
                                        "rule":{
                                            "properties" : {
                                                "id": {"type":"keyword"},
                                                "name": {"type":"text"},
                                                "description": {"type":"text"},
                                                "severity": {"type":"keyword"},
                                                "mitre_attack": {
                                                    "type": "object",
                                                    "properties" : {
                                                        "tactic": {"type":"keyword"},
                                                        "technique_id": {"type":"keyword"},
                                                        "subtechnique_id": {"type":"keyword"},
                                                        "data_sources": {"type":"keyword"},
                                                    }
                                                },
                                                "platform": {"type":"keyword"},

                                                // inclustion 내
                                                "stage_id": {"type":"keyword"},
                                                "action": {"type":"keyword"},
                                                "action_message": {"type":"keyword"},

                                                "operational_usage": {"type":"text"},
                                                "false_positive": {"type":"text"}
                                            }
                                        }

                                    }
                                }
                            }
                        }
                    }
                }
            -> 1.C raw-xdr
            -> 2.A security-threat
                -> SIEM 정규화된 포맷형식의 위협 결과 포맷
                {
                    "template" : {
                        "settings": {
                            "number_of_shards":   4,
			                "number_of_replicas": 1,
                        },
                        "mappings": {
                            "properties" : {
                                "platform": {"type": "keyword"},            // 이벤트 전송한 플랫폼 ( ndr, xdr, edr, soar 등)
                                "timestamp_nano": {"type": "long"},         // 타임스탬프 나노값
                                "event_id": {"type": "keyword"},            // 이벤트 id 값

                                "severity": {"type": "keyword"},            // 심각도

                                "topic": {"type": "keyword"},               // 주제 
                                "description": {"type": "text"},            // 해당 위협 기술
                                "response_description": {"type": "text"},   // 차단 방법 기술
                                "detected_method": {"type": "keyword"}      // 해당 이벤트 탐지된 방법 ( signature 또는 ai )
                                
                                
                            }
                        }
                    }
                }  
    */
    SIEM::Server::SIEM_CORE siem;
    std::cout << siem.Query__Timestamp__raw_edr_with_Range(1730102000000000000, 1730104015000000000).dump();

    // Initialize-2-A security-threat

    /*
        RestAPI 기능으로 Opening
    */

    httplib::Server APIsvr;
    std::string APIsvr_IP = "0.0.0.0";
    unsigned long APIsvr_PORT = 10900;
    
    // 보안 이벤트 다큐멘트 전송
     APIsvr.Post(
        "/api/solution/siem/push/event/security-threat",
        [&siem](const httplib::Request& req, httplib::Response& res)
        {}
     );

    // RestAPI - Server실행 
    APIsvr.listen(
        APIsvr_IP,
        APIsvr_PORT
    );

    return 0;
}