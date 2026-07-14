import nmap
import sys
import json
# 앞서 만든 parser.py에서 NmapParser를 가져옵니다.
from parser import NmapParser

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
        return parser.to_dict()

    except Exception as e:
        return {
            "success": False,
            "error": f"스캔 과정 중 예외 오류 발생: {str(e)}",
            "hosts": []
        }

# =====================================================================
# 단독으로 실행(테스트)할 때만 작동하는 블록
# =====================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("    Nmap 정제 데이터 반환 스캐너 테스트")
    print("=" * 60)
    
    target_input = input("스캔할 IP 주소 또는 도메인을 입력하세요 (예: 127.0.0.1): ").strip()
    if not target_input:
        print("[-] 대상이 입력되지 않아 종료합니다.")
        sys.exit(0)
        
    print(f"[*] {target_input}을 대상으로 스캔을 시작합니다 (Nmap 주요 1,000개 포트)...")
    
    # 함수를 호출하여 가공된 딕셔너리 데이터를 리턴받음
    result_data = run_scanner(target_input, arguments='-sV')
    
    print("\n--- [스캔 완료! 리턴받은 딕셔너리 결과 출력] ---")
    # 반환받은 딕셔너리를 눈으로 보기 편하게 가공해서 출력
    print(json.dumps(result_data, ensure_ascii=False, indent=4))