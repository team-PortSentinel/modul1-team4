import json
import os
from pprint import pprint

# dotenv 모듈 임포트
from dotenv import load_dotenv

# 2팀에서 작성한 모듈 임포트 (패키지 구조에 맞게 수정 필요)
from team2_module.vulnerability_service import analyze_services
from team2_module.service_analysis_module import flatten_team1_scan_output

def main():
    # 1. .env 파일에서 환경변수 로드
    load_dotenv()
    
    # 필수 API 키 확인
    if not os.getenv("VULNERS_API_KEY"):
        print("[경고] VULNERS_API_KEY가 설정되지 않았습니다. .env 파일을 확인해 주세요.")
        # 키가 없으면 VulnersClient 에러가 발생할 수 있습니다.
        
    if not os.getenv("NVD_API_KEY"):
        print("[안내] NVD_API_KEY가 설정되지 않았습니다. NVD 조회 속도가 제한될 수 있습니다.")

    input_filename = "nmap_output_team1_example.json"
    output_filename = "team3_input_data.json"

    print("\n[1/4] 1팀의 JSON 데이터 로드 중...")
    try:
        with open(input_filename, "r", encoding="utf-8") as f:
            team1_data = json.load(f)
    except FileNotFoundError:
        print(f"[오류] {input_filename} 파일을 찾을 수 없습니다.")
        return

    print("[2/4] 서비스 데이터 평탄화 (Flattening) 진행 중...")
    # 1팀 데이터를 2팀 표준 입력 형식(ServiceInput 기반)으로 평탄화
    flat_services = flatten_team1_scan_output(team1_data)
    print(f" -> 총 {len(flat_services)}개의 서비스(포트)가 인식되었습니다.")

    print("[3/4] NVD/Vulners API 취약점 스캔 및 3팀 데이터 포맷팅 진행 중...")
    # API 요청이 여러 번 발생하므로 시간이 다소 소요될 수 있습니다.
    analysis_result = analyze_services(flat_services)
    
    # 3팀에게 전달할 실제 list[dict] 데이터
    team3_records = analysis_result.get("team3_records", [])

    print(f"\n[!] 분석 완료: 3팀 전달용 데이터 총 {len(team3_records)}건 생성됨.")

    # 추출된 데이터가 잘 나왔는지 앞의 2개만 출력해서 검증
    if team3_records:
        print("\n=== 3팀 전달용 데이터 샘플 (상위 2건) ===")
        for i, record in enumerate(team3_records[:2]):
            print(f"\n[Record {i+1}]")
            pprint(record, sort_dicts=False)

    print(f"\n[4/4] 3팀 전달용 결과를 '{output_filename}'에 저장합니다.")
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(team3_records, f, ensure_ascii=False, indent=4)
        
    print("[+] 모든 과정이 완료되었습니다. 결과 파일을 확인해 보세요!")

if __name__ == "__main__":
    main()