# siem_core.py

import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, NotFoundError
from typing import List, Dict, Any, Optional

# es_templates.py에서 템플릿 정의 가져오기
from Server.Core.ElasticSearch.es_templates import (
    RAW_NDR_INDEX_TEMPLATE, RAW_NDR_INDEX_TEMPLATE_NAME,
    RAW_EDR_INDEX_TEMPLATE, RAW_EDR_INDEX_TEMPLATE_NAME,
    RAW_XDR_INDEX_TEMPLATE_NAME, RAW_XDR_INDEX_TEMPLATE,
    SECURITY_THREAT_INDEX_TEMPLATE, SECURITY_THREAT_INDEX_TEMPLATE_NAME
    
)

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def nano_to_iso_string(nanoseconds: Optional[int]) -> Optional[str]:
    if(nanoseconds == None):
        return None
    """
    19자리 나노초 정수를 ISO 8601 UTC 문자열로 변환합니다.
    예: 1730105630112233500 -> "2024-10-28T09:33:50.112233500Z"
    """
    # 초(seconds)와 나노초(nanoseconds part)로 분리
    seconds = nanoseconds // 1_000_000_000
    nanos_part = nanoseconds % 1_000_000_000
    
    # UTC 기준으로 datetime 객체 생성
    dt_object = datetime.fromtimestamp(seconds, tz=timezone.utc)
    
    # YYYY-MM-DDTHH:MM:SS 형식으로 포맷팅
    base_format = dt_object.strftime('%Y-%m-%dT%H:%M:%S')
    
    # 나노초 부분을 9자리로 맞춰서 결합하고 Z를 붙여 UTC임을 명시
    return f"{base_format}.{nanos_part:09d}Z"

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
            RAW_XDR_INDEX_TEMPLATE_NAME: RAW_XDR_INDEX_TEMPLATE,
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

    def _push_event(self, index_name_prefix:str, event_doc: Dict[str, Any]) -> bool:
        '''
         args: index_name_prefix
            -> e.g. "security-threat", "raw-edr"
        '''
    
        try:
            index_name = self._make_index_name_by_date(index_name_prefix)
            response = self.es_client.index(index=index_name, document=event_doc)
            return response.get('result') in ['created', 'updated']
        except Exception as e:
            logging.error(f"security-threat 이벤트 추가 실패: {e}")
            return False

    def push_security_threat_event(self, event_doc: Dict[str, Any]) -> bool:
        """
        security-threat 이벤트를 Elasticsearch에 추가.
        """
        return self._push_event("security-threat", event_doc)
    def push_raw_edr_event(self, event_doc: Dict[str, Any]) -> bool:
        """
            raw-edr 이벤트를 Elasticsearch에 추가.
        """
        return self._push_event("raw-edr", event_doc)
    def push_raw_ndr_event(self, event_doc: Dict[str, Any]) -> bool:
        """
            raw-ndr 이벤트를 Elasticsearch에 추가.
        """
        return self._push_event("raw-ndr", event_doc)
    def push_raw_xdr_event(self, event_doc: Dict[str, Any]) -> bool:
        """
            raw-xdr 이벤트를 Elasticsearch에 추가.
        """
        return self._push_event("raw-xdr", event_doc)
    
    def _siem_query(self, index_pattern:str, query_data:dict) -> dict:
        return dict( self.es_client.search(
                index=index_pattern,
                body=query_data
            ).body )

    def _siem_query_simple_index_range_timestamp(self, index_pattern: str, start_timestamp_nano_iso: str, end_timestamp_nano_iso: str, size: int = 1000) -> Dict[str, Any]:
        """
        최상위 레벨에 타임스탬프 필드가 있는 단순 구조의 인덱스를 쿼리하는 헬퍼 함수.
        (e.g., security-threat)
        """
        query_body = {
            "query": {
                "range": {
                    "timestamp_nano_iso8601": {  # <--- 'events.' 접두사가 없음
                        "gte": start_timestamp_nano_iso,
                        "lte": None if len( end_timestamp_nano_iso ) == 0 else end_timestamp_nano_iso
                    }
                }
            },
            "sort": [
                {"timestamp_nano": {"order": "asc"}} # <--- nested 컨텍스트가 필요 없음
            ]
        }
        import json 
        print(
            json.dumps( query_body )
        )
        
        try:
            response_dict = self.es_client.search(
                index=index_pattern,
                body=query_body,
                size=size
            ).body
            
            total_hits = response_dict['hits']['total']['value']
            logs = [hit['_source'] for hit in response_dict['hits']['hits']]
            
            return {"total": total_hits, "logs": logs}
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"total": 0, "logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"total": 0, "logs": [], "error": str(e)}
        
    def _siem_query_simple_index_searchAfter(self, index_pattern:str, search_after_value:int, size:int = 10)-> Dict[str, List[Dict]]:
        query_body = {
            "sort" : [
                {
                    "timestamp_nano_iso8601": {
                        "order": "asc"
                    }
                }
            ],
            "search_after": [ search_after_value ] 
        }
        
        try:
            response_dict = self.es_client.search(
                index=index_pattern,
                body=query_body, # 전체 쿼리 본문을 'body' 파라미터로 전달
                size=size
            )
            total_hits = response_dict['hits']['total']['value']
            logs = [ { "source" : hit['_source'], "id": hit["_id"], "sort": hit.get("sort", None) } for hit in response_dict['hits']['hits']]
            
            return {"total": total_hits, "logs": logs}
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"logs": []}
        
    def _siem_query_raw_index_searchAfter(self, index_pattern:str, search_after_value:int, size:int = 1)-> Dict[str, List[Dict]]:
        query_body = {
            "sort" : [
                {
                    "timestamp.first_seen_iso8601": {
                        "order": "asc"
                    }
                }
            ],
            "search_after": [ search_after_value ] 
        }
        
        try:
            response_dict = self.es_client.search(
                index=index_pattern,
                body=query_body, # 전체 쿼리 본문을 'body' 파라미터로 전달
                size=size
            )
            total_hits = response_dict['hits']['total']['value']
            logs = [ { "source" : hit['_source'], "id": hit["_id"], "sort": hit.get("sort", None) } for hit in response_dict['hits']['hits']]
            
            return {"total": total_hits, "logs": logs}
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"logs": []}
        
        
    def _siem_query_raw_index_root_session(self, index_pattern: str, root_session_id:str, size: int = 1000) -> Dict[str, List[Dict]]:
        """
            raw 계열 인덱스에서 {세션 내} 세션 쿼리하는 내부 헬퍼 함수
        """
        query_body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "header.root_sessionid": root_session_id
                            }
                        }
                    ]
                }
            },
            "sort": [
                { "header.timestamp_nano_iso8601": "asc" }
            ]
            
        }
        
        try:
            response_dict = self.es_client.search(
                index=index_pattern,
                body=query_body, # 전체 쿼리 본문을 'body' 파라미터로 전달
                size=size
            )
            total_hits = response_dict['hits']['total']['value']
            logs = [hit['_source'] for hit in response_dict['hits']['hits']]
            
            return {"total": total_hits, "logs": logs}
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"logs": []}
        
        
    def _siem_query_raw_index_range_timestamp(self, index_pattern: str, start_timestamp_nano_iso: str, end_timestamp_nano_iso: str, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw 계열 인덱스에서 타임스탬프 범위로 쿼리하는 내부 헬퍼 함수
        """
        
        query_body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "header.timestamp_nano_iso8601": {
                                    "gte": start_timestamp_nano_iso,
                                    "lte":  None if end_timestamp_nano_iso == None or len( end_timestamp_nano_iso ) == 0 else end_timestamp_nano_iso
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                { "header.timestamp_nano_iso8601": "asc" }
            ]
            
        }
        
        try:
            response_dict = self.es_client.search(
                index=index_pattern,
                body=query_body, # 전체 쿼리 본문을 'body' 파라미터로 전달
                size=size
            )
            total_hits = response_dict['hits']['total']['value']
            logs = [hit['_source'] for hit in response_dict['hits']['hits']]
            return {"total": total_hits, "logs": logs}
            
        except NotFoundError:
            logging.warning(f"인덱스 패턴 '{index_pattern}'을(를) 찾을 수 없습니다.")
            return {"logs": []}
        except Exception as e:
            logging.error(f"'{index_pattern}' 쿼리 실패: {e}")
            return {"logs": []}


    
    
    def query_raw_edr_search_after(self, search_after_value: int, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-edr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_searchAfter("raw-edr-*", search_after_value, size)
    
    #############################################################################################################################################################################
    
    def query_timestamp_raw_edr_with_root_session(self, root_session_id:str, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-edr 인덱스에서 지정된 루트 세션전체 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_root_session("raw-edr-*", root_session_id, size)
    
    def query_timestamp_raw_ndr_with_root_session(self, root_session_id:str, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-ndr 인덱스에서 지정된 루트 세션전체 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_root_session("raw-ndr-*", root_session_id, size)
    
    #############################################################################################################################################################################
    
    def query_timestamp_raw_ndr_with_range(self, start_timestamp: int, end_timestamp: int, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-ndr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_range_timestamp("raw-ndr-*", nano_to_iso_string(start_timestamp), nano_to_iso_string(end_timestamp), size)

    def query_timestamp_raw_edr_with_range(self, start_timestamp: int, end_timestamp: int, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-edr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_raw_index_range_timestamp("raw-edr-*", nano_to_iso_string(start_timestamp), nano_to_iso_string(end_timestamp), size)
    
    def query_timestamp_security_threat_with_range(self, start_timestamp: int, end_timestamp: int, size: int = 1000) -> Dict[str, List[Dict]]:
        """
        raw-edr 인덱스에서 지정된 시간 범위의 문서를 쿼리합니다.
        """
        return self._siem_query_simple_index_range_timestamp("security-threat-*", nano_to_iso_string(start_timestamp), nano_to_iso_string(end_timestamp), size)