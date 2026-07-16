import nmap
# 앞서 만든 parser.py에서 NmapParser를 가져옵니다.
from utils.parser import NmapParser

def run_scanner(target, arguments='-sV'):
    # 1. 드라이브가 다르거나 환경변수가 불안정할 때를 대비해 C드라이브 절대 경로 탐색 포함
    try:
        nm = nmap.PortScanner()
    except Exception as e:
        return {
            "success": False,
            "error": f"Nmap 실행 파일을 찾을 수 없습니다. 설치 혹은 PATH 설정을 확인하세요. ({e})",
            "hosts": []
        }
    

    # 2. 포트 범위를 생략하고 Nmap 자체 기본 1,000개 주요 포트 스캔을 수행
    try:
        # arguments 기본값: '-sV' (열린 포트의 서비스 버전 상세 인지)
        # 운영체제 식별까지 원하시면 '-sV -O'로 넘겨줄 수 있습니다 (다만 -O는 관리자 권한 필요)
        raw_result = nm.scan(hosts=target, arguments=arguments)
        # 3. 파서 모듈을 사용해 중첩 데이터 구조를 깔끔한 딕셔너리로 가공
        parser = NmapParser(raw_result)
        
        return parser.to_json()

    except Exception as e:
        return {
            "success": False,
            "error": f"스캔 과정 중 예외 오류 발생: {str(e)}",
            "hosts": []
        }