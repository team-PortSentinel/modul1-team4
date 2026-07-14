import json
from dotenv import load_dotenv

load_dotenv()   # .env에서 키 읽기

from team2_module.vulnerability_service import analyze_services

# 팀1 형식 그대로, 분석할 서비스 하나만 직접 정의
services = [
    {
        "host": "192.168.129.129",
        "port": 80,
        "protocol": "TCP",
        "status": "open",
        "service": "http",
        "product": "Apache httpd",   # ← 여기가 제품
        "version": "2.4.18",          # ← 여기가 분석할 버전
        "vendor": None,
        "extra_info": None,
    }
]

result = analyze_services(
    services,
    use_web_search=False,
    max_cves=3,
    cpe_candidate_limit=10,
    minimum_cpe_score=0.55,
)

# 결과 요약 출력
for record in result.get("team3_records", []):
    print(
        f"{record.get('cve_id')} | "
        f"CVSS: {record.get('cvss_score')} | "
        f"등급: {record.get('severity')} | "
        f"{record.get('product')} {record.get('version')}"
    )

# ===== CPE 확인용 =====
print("\n" + "=" * 40)
print("CPE 매칭 확인")
print("=" * 40)
for svc in result["services"]:
    s = svc["service"]
    print(f"제품: {s['product']} {s['version']}")
    print(f"조회 방식: {svc.get('query_method')}")
    print(f"선택된 CPE: {svc.get('selected_cpe')}")
    print("-" * 40)

# 전체 상세(웹서치 포함) 보고 싶으면 주석 해제
print(json.dumps(result["services"], ensure_ascii=False, indent=2))