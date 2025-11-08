from Server.RestAPI import SIEM_API_SERVER


if __name__ == "__main__":
    # SIEM API 서버 인스턴스 생성 및 실행
    api_server = SIEM_API_SERVER()
    
    # C++ 코드의 테스트 쿼리 예시 실행
    print("\n[테스트] raw-edr 시간 범위 쿼리 실행...")
    test_results = api_server.siem_core.query_timestamp_raw_edr_with_range(1730102000000000000, 1730104015000000000)
    import json
    print(json.dumps(test_results, indent=2))
    print("[테스트] 쿼리 완료.\n")
    
    # API 서버 실행
    api_server.run()