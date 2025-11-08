from Server.RestAPI import SIEM_API_SERVER


if __name__ == "__main__":
    # SIEM API 서버 인스턴스 생성 및 실행
    api_server = SIEM_API_SERVER()
    
    # API 서버 실행
    api_server.run()