#ifndef ELASITCSEARCH_HPP
#define ELASITCSEARCH_HPP

#include "../../Util/util.hpp"

#include "ES_Helper/ElasticSearchGlobal.hpp"

namespace SIEM
{
    namespace Server
    {
        namespace Elasticsearch
        {
            struct ElasticSearch_Query_Output
            {
                unsigned long long took;
                bool timed_out;
                struct
                {
                    unsigned long long total;
                    unsigned long long successful;
                    unsigned long long skipped;
                    unsigned long long failed;
                }_shards;
                struct
                {
                    struct
                    {
                        unsigned long long value;
                        std::string relation;
                    }total;
                    
                    std::vector<json> hits;

                }hits;
            };

            class ElasticSearcher
            {
                public:
                    ElasticSearcher(
                        std::string ip = "localhost",
                        unsigned long port = 9200
                    ): client(ip, port)
                    {}

                    // 인덱스 존재 여부 확인
                    bool IndexExists(const std::string& indexName)
                    {
                        
                        auto res = client.Get(("/_index_template/" + indexName).c_str());
                        if (!res)
                            throw std::runtime_error("Failed to connect to Elasticsearch");

                        std::cout << res->status;

                        return res->status == 200;
                    }

                    bool CreateIndex(const std::string& indexName, const std::string& body = "{}")
                    {
                        if (IndexExists(indexName))
                        {
                            std::cout << "[INFO] Index '" << indexName << "' already exists.\n";
                            return true;
                        }

                        std::string path = "/_index_template/" + indexName;
                        auto res = client.Put(path.c_str(), body, "application/json");
                        if (res && (res->status == 200 || res->status == 201))
                        {
                            std::cout << "[INFO] Index template '" << indexName << "' created successfully.\n";
                            return true;
                        }
                        else if (res)
                        {
                            std::cerr << "[ERROR] Failed to create index template '" << indexName 
                                    << "'. Status: " << res->status << ", Body: " << res->body << std::endl;
                            return false;
                        }
                        else
                        {
                            std::cerr << "[ERROR] Failed to connect to Elasticsearch for creating template '" << indexName << "'.\n";
                            return false;
                        }
                    }
                    bool CreateIndex(const std::string& indexName, const json& body = json::object())
                    {
                        if (IndexExists(indexName))
                        {
                            std::cout << "[INFO] Index '" << indexName << "' already exists.\n";
                            return true;
                        }

                        std::string path = "/_index_template/" + indexName;
                        auto res = client.Put(path.c_str(), body.dump(), "application/json");
                        if (res && (res->status == 200 || res->status == 201))
                        {
                            std::cout << "[INFO] Index template '" << indexName << "' created successfully.\n";
                            return true;
                        }
                        else if (res)
                        {
                            std::cerr << "[ERROR] Failed to create index template '" << indexName 
                                    << "'. Status: " << res->status << ", Body: " << res->body << std::endl;
                            return false;
                        }
                        else
                        {
                            std::cerr << "[ERROR] Failed to connect to Elasticsearch for creating template '" << indexName << "'.\n";
                            return false;
                        }
                    }

                    bool AddDocument(const std::string& indexName, const std::string& doc)
                    {
                        auto path = "/" + indexName + "-" + MakeIndexNameByDate() + "/_doc";
                        auto res = client.Put(path.c_str(), doc, "application/json");
                        return res && (res->status == 200 || res->status == 201);
                    }
                    bool AddDocument(const std::string& indexName, const json& doc)
                    {
                        auto path = "/" + indexName + "-" + MakeIndexNameByDate() + "/_doc";
                        auto res = client.Put(path.c_str(), doc.dump(), "application/json");
                        return res && (res->status == 200 || res->status == 201);
                    }
                    bool QueryDocument(const std::string& indexpattern, const std::string& query_body,  ElasticSearch_Query_Output& output)
                    {
                        std::string path = "/"+indexpattern+"/_search";
                        auto res = client.Post(path.c_str(), query_body.c_str(), "application/json");
                        std::cout << path;
                        if (!res) {
                            std::cerr << "[ERROR] Elasticsearch connection failed.\n";
                            return false;
                        }

                        if (res->status != 200) {
                            std::cerr << "[ERROR] Query failed. Status: " << res->status
                                    << " | Body: " << res->body << std::endl;
                            return false;
                        }

                        return PostIndexQuery_to_Sturct(res->body, output);
                    }
                    bool QueryDocument(const std::string& indexpattern, const json& query_body, ElasticSearch_Query_Output& output)
                    {
                        
                        std::string path = "/"+indexpattern+"/_search";
                        auto res = client.Post(path.c_str(), query_body.dump(), "application/json");

                        if (!res) {
                            std::cerr << "[ERROR] Elasticsearch connection failed.\n";
                            return false;
                        }

                        if (res->status != 200) {
                            std::cerr << "[ERROR] Query failed. Status: " << res->status
                                    << " | Body: " << res->body << std::endl;
                            return false;
                        }

                        return PostIndexQuery_to_Sturct(res->body, output);
                    }

                private:
                    std::string ConnectionURI;
                    httplib::Client client;

                    std::string MakeIndexNameByDate() {
                        // 현재 시스템 시간 가져오기
                        // -> "2025-02-22" 식으로
                        std::time_t now = std::time(nullptr);
                        std::tm t;
                        localtime_r(&now, &t);  // 로컬 타임 기준, gmtime_r로 하면 UTC

                        // YYYY-MM-DD 형식으로 포맷
                        char buf[32];
                        std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                                    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);

                        return std::string(buf);
                    }

                    bool PostIndexQuery_to_Sturct(const std::string& query_response_body, ElasticSearch_Query_Output& output)
                    {

                        try {
                            json j = json::parse(query_response_body);

                            output.took = j.value("took", 0ULL);
                            output.timed_out = j.value("timed_out", false);

                            // _shards
                            if (j.contains("_shards")) {
                                output._shards.total = j["_shards"].value("total", 0ULL);
                                output._shards.successful = j["_shards"].value("successful", 0ULL);
                                output._shards.skipped = j["_shards"].value("skipped", 0ULL);
                                output._shards.failed = j["_shards"].value("failed", 0ULL);
                            }

                            // hits.total
                            if (j.contains("hits")) {
                                auto& hitsObj = j["hits"];
                                if (hitsObj.contains("total")) {
                                    output.hits.total.value = hitsObj["total"].value("value", 0ULL);
                                    output.hits.total.relation = hitsObj["total"].value("relation", "");
                                }

                                // hits 배열 저장 (json 그대로 vector에 push)
                                if (hitsObj.contains("hits") && hitsObj["hits"].is_array()) {
                                    output.hits.hits.clear();
                                    for (auto& hit : hitsObj["hits"]) {
                                        output.hits.hits.push_back(hit);
                                    }
                                }
                            }

                        } catch (std::exception& e) {
                            std::cerr << "[ERROR] Failed to parse Elasticsearch response: " << e.what() << std::endl;
                            return false;
                        }
                        return true;
                    }
                    
            };
        }
    }
}

#endif