# siem_core.py

import logging
from datetime import datetime
from elasticsearch import Elasticsearch, NotFoundError
from typing import List, Dict, Any

# es_templates.py에서 템플릿 정의 가져오기
from Server.Core.ElasticSearch.es_templates import (
    RAW_NDR_INDEX_TEMPLATE, RAW_NDR_INDEX_TEMPLATE_NAME,
    RAW_EDR_INDEX_TEMPLATE, RAW_EDR_INDEX_TEMPLATE_NAME,
    SECURITY_THREAT_INDEX_TEMPLATE, SECURITY_THREAT_INDEX_TEMPLATE_NAME
)

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SIEM_CORE:
    def __init__(self, host: str = "localhost", port: int = 9200):
        """
        SIEM_CORE 클래스 초기화 및 Elasticsearch 연결
        """
        try:
            self.es_client = Elasticsearch(hosts=[{'host': host, 'port': port, 'scheme': 'http'}])
            if not self.es_client.ping():
                raise ConnectionError("Elasticsearch에 연결할 수 없습니다.")
            logging.info("Elasticsearch에 성공적으로 연결되었습니다.")
            self._initialize_templates()
        except Exception as e:
            logging.error(f"SIEM_CORE 초기화 실패: {e}")
            raise

    def _initialize_templates(self):
        """
        필요한 Elasticsearch 인덱스 템플릿이 없으면 생성합니다.
        """
        templates_to_check = {
            RAW_NDR_INDEX_TEMPLATE_NAME: RAW_NDR_INDEX_TEMPLATE,
            RAW_EDR_INDEX_TEMPLATE_NAME: RAW_EDR_INDEX_TEMPLATE,
            SECURITY_THREAT_INDEX_TEMPLATE_NAME: SECURITY_THREAT_INDEX_TEMPLATE
        }

        for name, body in templates_to_check.items():
            try:
                try:
                    self.es_client.indices.get_index_template(name=name)
                    logging.info(f"인덱스 템플릿 '{name}'이(가) 이미 존재합니다.")
                except NotFoundError:
                    self.es_client.indices.put_index_template(name=name, **body)
                    logging.info(f"인덱스 템플릿 '{name}'이(가) 성공적으로 생성되었습니다.")
            except Exception as e:
                logging.error(f"인덱스 템플릿 '{name}' 생성 실패: {e}")
                raise

    def _make_index_name_by_date(self, prefix: str) -> str:
        """
        'prefix-YYYY-MM-DD' 형식의 인덱스 이름을 생성합니다.
        """
        return f"{prefix}-{datetime.utcnow().strftime('%Y-%m-%d')}"

    def push_security_threat_event(self, event_doc: Dict[str, Any]) -> bool:
        """
        security-threat 이벤트를 Elasticsearch에 추가합니다.
        """
        try:
            index_name = self._make_index_name_by_date("security-threat")
            response = self.es_client.index(index=index_name, document=event_doc)
            return response.get('result') in ['created', 'updated']
        except Exception as e:
            logging.error(f"security-threat 이벤트 추가 실패: {e}")
            return False

    def _siem_query_raw_index_range_timestamp(self, index_pattern: str, start_timestamp: int, end_timestamp: int) -> Dict[str, List[Dict]]:
        """
        raw 계열 인덱스에서 타임스탬프 범위로 쿼리하는 내부 헬퍼 함수
        """
        query_body = {
            "query": {
                "range": {
                    "events.timestamp_nano": {
                        "gte": start_timestamp,
                        "lte": end_timestamp
                    }
                }
            },
            "sort": [
                {"events.timestamp_nano": {"order": "asc"}}
            ]
        }

        try:
            response = self.es_client.search(
                index=index_pattern,
                body=query_body, # 전체 쿼리 본문을 'body' 파라미터로 전달
                size=1000
            )
            
            output = {"logs": []}
            for hit in response['hits']['hits']:
                if '_source' in hit:
                    output["logs"].append(hit['_source'])
            return output
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"logs": []}


    def query_timestamp_raw_ndr_with_range(self, start_timestamp: int, end_timestamp: int) -> Dict[str, List[Dict]]:
        """
        raw-ndr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_range_timestamp("raw-ndr-*", start_timestamp, end_timestamp)

    def query_timestamp_raw_edr_with_range(self, start_timestamp: int, end_timestamp: int) -> Dict[str, List[Dict]]:
        """
        raw-edr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_range_timestamp("raw-edr-*", start_timestamp, end_timestamp)