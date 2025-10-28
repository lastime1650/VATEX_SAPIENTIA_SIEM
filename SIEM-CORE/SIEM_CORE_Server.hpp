#ifndef SIEM_CORE_SERVER_HPP
#define SIEM_CORE_SERVER_HPP

#include "../Util/util.hpp"
#include "Elasticsearch/ElasticSearcher.hpp"



namespace SIEM
{
    namespace Server
    {
        namespace Requests
        {
        }

        class SIEM_CORE
        {
            public:
                SIEM_CORE(
                    std::string ip = "localhost",
                    unsigned long port = 9200
                ):ES(ip, port)
                {
                    // 초기화
                    /*
                        Initialize 진행
                    */
                    // Initialize-1-A raw-ndr
                    if( !this->ES.IndexExists("raw-ndr-index-template") )
                    {
                        // 없는 경우 생성
                        if( !this->ES.CreateIndex("raw-ndr-index-template", SIEM::Server::Elasticsearch::Global::Index_Templates::raw_ndr_index_template) )
                            throw std::runtime_error("raw-ndr-index-template "); // index create failed
                    }


                    // Initialize-1-B raw-edr
                    if( !this->ES.IndexExists("raw-edr-index-template") )
                    {
                        // 없는 경우 생성
                        if( !this->ES.CreateIndex("raw-edr-index-template", SIEM::Server::Elasticsearch::Global::Index_Templates::raw_edr_index_template) )
                            throw std::runtime_error("raw-edr-index-template "); // index create failed
                    }


                    // Initialize-1-C raw-xdr
                    /*...*/

                    // Initialize-2-A security-threat
                    if( !this->ES.IndexExists("security-threat-index-template") )
                    {
                        // 없는 경우 생성
                        if( !this->ES.CreateIndex("security-threat-index-template", SIEM::Server::Elasticsearch::Global::Index_Templates::security_threat_index_template) )
                            throw std::runtime_error("security-threat-index-template "); // index create failed
                    }
                }

                /*
                    Timestamp기반 쿼리
                */
                // 1. 시간 범위형 쿼리

                // 1-A. raw-ndr 인덱스
                json Query__Timestamp__raw_ndr_with_Range(
                    unsigned long long StartTimestamp,
                    unsigned long long EndTimestamp
                ){
                    // timestamp targeted key location (이벤트를 생성한 시점 시간임)
                    /*
                        "template" -> mappings -> events(array_key) -> timestamp_nano(by sensor)
                    */
                    SIEM::Server::Elasticsearch::ElasticSearch_Query_Output Query_Response;
                    ES.QueryDocument(
                        "raw-ndr-*",
                        fmt::format(R"(
                            {{
                                "query" : {{
                                    "range" : {{
                                        "events.timestamp_nano" : {{
                                            "gte": {},
                                            "lte": {}
                                        }}
                                    }}
                                }},
                                "sort": [
                                    {{ "events.timestamp_nano" : {{ "order": "asc" }} }}
                                ]
                            }}
                        )",StartTimestamp, EndTimestamp),
                        Query_Response
                    );

                    json output = {
                        {"logs", json::array() }
                    };

                    for(auto hit : Query_Response.hits.hits)
                    {
                        
                        /*
                            > Example
                            {
                                "_id":"TvHLKZoB22D515OgDT_G",
                                "_index":"raw-ndr-test",
                                "_score":null,
                                
                                "_source":{
                                    "event_count":3,
                                    "events":{
                                        "direction":"out","dst_ip":"10.0.0.12","dst_port":3306,"interfacename":"eth1","protocol":"TCP","rule":{"description":"MySQL connection","id":"R010","severity":"medium","stage_action":"allow","stage_action_message":"Database access","stage_index_name":"DB","stage_node_location_index":10},"src_ip":"10.1.0.1","src_port":3306,"timestamp_nano":1730102720000000000},"flow_session_id":"flow-jjj","sensor_id":"sensor-010","session_first_seen_nano":1730102700000000000,"session_last_seen_nano":1730103000000000000
                                    },
                                "sort":[1730102720000000000]
                            }
                        */
                        if (hit.contains("_source"))
                        {
                            output["logs"].push_back(hit["_source"]);
                        }

                    }
                    return output;
                }

                json Query__Timestamp__raw_edr_with_Range(
                    unsigned long long StartTimestamp,
                    unsigned long long EndTimestamp
                ){
                    // timestamp targeted key location (이벤트를 생성한 시점 시간임)
                    /*
                        "template" -> mappings -> events(array_key) -> timestamp_nano(by sensor)
                    */
                    SIEM::Server::Elasticsearch::ElasticSearch_Query_Output Query_Response;
                    ES.QueryDocument(
                        "raw-edr-*",
                        fmt::format(R"(
                            {{
                                "query" : {{
                                    "range" : {{
                                        "events.timestamp_nano" : {{
                                            "gte": {},
                                            "lte": {}
                                        }}
                                    }}
                                }},
                                "sort": [
                                    {{ "events.timestamp_nano" : {{ "order": "asc" }} }}
                                ]
                            }}
                        )",StartTimestamp, EndTimestamp),
                        Query_Response
                    );

                    json output = {
                        {"logs", json::array() }
                    };

                    for(auto hit : Query_Response.hits.hits)
                    {
                        
                        /*
                            > Example
                            {
                                "_id":"TvHLKZoB22D515OgDT_G",
                                "_index":"raw-ndr-test",
                                "_score":null,
                                
                                "_source":{
                                    "event_count":3,
                                    "events":{
                                        "direction":"out","dst_ip":"10.0.0.12","dst_port":3306,"interfacename":"eth1","protocol":"TCP","rule":{"description":"MySQL connection","id":"R010","severity":"medium","stage_action":"allow","stage_action_message":"Database access","stage_index_name":"DB","stage_node_location_index":10},"src_ip":"10.1.0.1","src_port":3306,"timestamp_nano":1730102720000000000},"flow_session_id":"flow-jjj","sensor_id":"sensor-010","session_first_seen_nano":1730102700000000000,"session_last_seen_nano":1730103000000000000
                                    },
                                "sort":[1730102720000000000]
                            }
                        */
                        if (hit.contains("_source"))
                        {
                            output["logs"].push_back(hit["_source"]);
                        }

                    }
                    return output;
                }

                SIEM::Server::Elasticsearch::ElasticSearcher ES;
            //private:
                
        };
    }
}

#endif