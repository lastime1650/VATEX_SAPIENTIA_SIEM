# main.py

import json
import uvicorn
from fastapi import FastAPI, APIRouter, Body,Query, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any, Union, Optional
import time

from Server.Core.siem_core import SIEM_CORE

class SIEM_API_SERVER:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200, server_ip: str = "0.0.0.0", server_port: int = 10900):
        self.server_ip = server_ip
        self.server_port = server_port
        
        # FastAPI 앱 및 라우터 초기화
        self.app = FastAPI(title="SIEM CORE API", version="1.0.0")
        self.router = APIRouter()
        self._add_routes()
        self.app.include_router(self.router)
        
        # SIEM Core 인스턴스 생성
        try:
            self.siem_core = SIEM_CORE(host=es_host, port=es_port)
        except Exception as e:
            # SIEM Core 초기화 실패 시 서버 실행 중단
            raise RuntimeError(f"SIEM Core를 시작할 수 없습니다: {e}")

    def _add_routes(self):
        """API 라우터에 추가합니다."""
        
        # 1. Index Push 계열
        self.router.post("/api/solution/siem/event/push/security-threat",)(self.event_push_security_threat)
        self.router.post("/api/solution/siem/event/push/raw-edr",)(self.event_push_raw_edr)
        self.router.post("/api/solution/siem/event/push/raw-ndr",)(self.event_push_raw_ndr)

        # 2. Index Query 계열
        # 2-A. Timestamp Range ( GET Method )
        self.router.get("/api/solution/siem/event/query/timestamp-range/security-threat",)(self.event_query_timestamp_range_security_threat)
        self.router.get("/api/solution/siem/event/query/timestamp-range/raw-edr",)(self.event_query_timestamp_range_raw_edr)
        self.router.get("/api/solution/siem/event/query/timestamp-range/raw-ndr",)(self.event_query_timestamp_range_raw_ndr)

    
    # 보안 이벤트 저장
    async def event_push_security_threat(self, event_doc: Dict[str, Any] = Body(...)):
        """
        /api/solution/siem/event/push/security-threat 엔드포인트 핸들러
        여러 보안 솔루션으로부터 받은 보안 위협 이벤트를 Elasticsearch에 저장
        """
        try:
            # 여기에 수신된 event_doc에 대한 유효성 검사 로직 추가 가능
            # 예: 필수 필드(platform, timestamp_nano 등) 존재 여부 확인
            
            Event = self._output_jsonData(event_doc)
            
            success = self.siem_core.push_security_threat_event( Event )
            if success:
                return self._create_success_response({"message": "Event successfully indexed."})
            else:
                return self._create_fail_response("Failed to index event into Elasticsearch.", status_code=500)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
        
    # raw-edr 이벤트 저장
    async def event_push_raw_edr(self, event_doc: Dict[str, Any] = Body(...)):
        """
        /api/solution/siem/event/push/raw-edr  핸들러
        {EDR} 로부터 받은 {프로세스 노드트리(부모-자식) 세션} 이벤트를 Elasticsearch에 저장.
        """
        try:
            # 여기에 수신된 event_doc에 대한 유효성 검사 로직 추가 가능
            # 예: 필수 필드(platform, timestamp_nano 등) 존재 여부 확인
            
            Event = self._output_jsonData(event_doc)
            
            success = self.siem_core.push_raw_edr_event( Event )
            if success:
                return self._create_success_response({"message": "Event successfully indexed."})
            else:
                return self._create_fail_response("Failed to index event into Elasticsearch.", status_code=500)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
        
    # raw-ndr 이벤트 저장
    async def event_push_raw_ndr(self, event_doc: Dict[str, Any] = Body(...)):
        """
        /api/solution/siem/event/push/raw-ndr  핸들러
        {NDR}로부터 받은 {네트워크 flow 세션} 이벤트를 Elasticsearch에 저장합니다.
        """
        try:
            # 여기에 수신된 event_doc에 대한 유효성 검사 로직 추가 가능
            # 예: 필수 필드(platform, timestamp_nano 등) 존재 여부 확인
            
            Event = self._output_jsonData(event_doc)
            
            success = self.siem_core.push_raw_ndr_event( Event )
            if success:
                return self._create_success_response({"message": "Event successfully indexed."})
            else:
                return self._create_fail_response("Failed to index event into Elasticsearch.", status_code=500)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
    
    
    # 2. Event Query
    
    async def event_query_timestamp_range_security_threat(self, start_nano_timestamp: int = Query(...), end_nano_timestamp: Optional[int] = Query( None ), size: int = Query(1000, description="페이지 당 결과 수", ge=1, le=100000)):
        """
        /api/solution/siem/event/query/timestamp-range/security-threat  핸들러
        {Platforms} 솔루션들 로부터 받은 이벤트를 시간 범위 + 사이즈 제공받아 쿼리 결과 전달
        """
        try:
            effective_end_ts = end_nano_timestamp
            if effective_end_ts is None:
                effective_end_ts = time.time_ns()
            
            
            # 입력값 유효성 검사
            if start_nano_timestamp >= effective_end_ts:
                return self._create_fail_response(
                    "start_nano_timestamp must be less than end_nano_timestamp.",
                    status_code=400
                )

            # SIEM 코어의 쿼리 함수 호출
            results = self.siem_core.query_timestamp_security_threat_with_range(
                start_nano_timestamp, 
                effective_end_ts,
                size
            )
            
            return self._create_success_response(results)

        except ValueError:
            return self._create_fail_response("Timestamps, size, and from must be valid integers.", status_code=400)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
    
    async def event_query_timestamp_range_raw_edr(self, start_nano_timestamp: int = Query(...), end_nano_timestamp: Optional[int] = Query( None ), size: int = Query(1000, description="페이지 당 결과 수", ge=1, le=100000)):
        """
        /api/solution/siem/event/query/timestamp-range/raw-edr  핸들러
        {EDR}로부터 받은 이벤트를 시간 범위 + 사이즈 제공받아 쿼리 결과 전달
        """
        try:
            
            effective_end_ts = end_nano_timestamp
            if effective_end_ts is None:
                effective_end_ts = time.time_ns()
                effective_end_ts += 162685890947713000

            # 입력값 유효성 검사
            if start_nano_timestamp >= effective_end_ts:
                return self._create_fail_response(
                    "start_nano_timestamp must be less than end_nano_timestamp.",
                    status_code=400
                )

            # SIEM 코어의 쿼리 함수 호출
            results = self.siem_core.query_timestamp_raw_edr_with_range(
                start_nano_timestamp, 
                effective_end_ts,
                size
            )
            
            return self._create_success_response(results)

        except ValueError:
            return self._create_fail_response("Timestamps, size, and from must be valid integers.", status_code=400)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
        
    async def event_query_timestamp_range_raw_ndr(self, start_nano_timestamp: int = Query(...), end_nano_timestamp: Optional[int] = Query( None ), size: int = Query(1000, description="페이지 당 결과 수", ge=1, le=100000)):
        """
        /api/solution/siem/event/query/timestamp-range/raw-ndr  핸들러
        {EDR}로부터 받은 이벤트를 시간 범위 + 사이즈 제공받아 쿼리 결과 전달
        """
        try:
            
            effective_end_ts = end_nano_timestamp
            if effective_end_ts is None:
                effective_end_ts = time.time_ns()
                

            # 입력값 유효성 검사
            if start_nano_timestamp >= effective_end_ts:
                return self._create_fail_response(
                    "start_nano_timestamp must be less than end_nano_timestamp.",
                    status_code=400
                )

            # SIEM 코어의 쿼리 함수 호출
            results = self.siem_core.query_timestamp_raw_ndr_with_range(
                start_nano_timestamp, 
                effective_end_ts,
                size
            )
            
            return self._create_success_response(results)

        except ValueError:
            return self._create_fail_response("Timestamps, size, and from must be valid integers.", status_code=400)
        except Exception as e:
            return self._create_fail_response(f"An unexpected error occurred: {str(e)}", status_code=500)
    
    
    
    
    # Util for APIServer
    def _output_jsonData(self, jsonData:any)->dict:
        if isinstance(jsonData, dict):
            return jsonData
        elif isinstance(jsonData, str):
            return json.loads(jsonData)
        elif isinstance(jsonData, bytes):
            return json.loads(jsonData)
        else:
            raise "Unknown Data Type!"
        
    def _create_success_response(self, output_data: Any) -> JSONResponse:
        """성공 응답 JSON을 생성합니다."""
        content = {
            "status": True,
            "output": output_data
        }
        return JSONResponse(content=content)

    def _create_fail_response(self, reason: str, status_code: int = 400) -> JSONResponse:
        """실패 응답 JSON을 생성합니다."""
        content = {
            "status": False,
            "fail_reason": reason
        }
        return JSONResponse(content=content, status_code=status_code)
    
    def run(self):
        """FastAPI 서버를 실행합니다."""
        print(f"SIEM CORE API 서버를 시작합니다... http://{self.server_ip}:{self.server_port}")
        uvicorn.run(self.app, host=self.server_ip, port=self.server_port)


