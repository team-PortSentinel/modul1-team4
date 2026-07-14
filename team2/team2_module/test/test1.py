import json
from pathlib import Path

from team2_module.service_analysis_module import flatten_team1_scan_output
from team2_module.vulnerability_service import analyze_services


def main() -> None:
    json_path = Path(__file__).parent / "nmap_output_team1_example.json"

    with json_path.open("r", encoding="utf-8") as file:
        team1_output = json.load(file)

    # print("=" * 80)
    # print("1. 팀 1 원본 JSON")
    # print("=" * 80)
    # print(json.dumps(team1_output, ensure_ascii=False, indent=2))

    normalized_services = flatten_team1_scan_output(team1_output)

    print("\n" + "=" * 80)
    print("2. 팀 2 입력용 평탄화 결과")
    print("=" * 80)
    print(json.dumps(normalized_services, ensure_ascii=False, indent=2))

    print("\n" + "=" * 80)
    print("3. NVD 기반 취약점 분석 시작")
    print("=" * 80)

    result = analyze_services(
        normalized_services,
        use_web_search=False,
        max_cves=10,
        cpe_candidate_limit=10,
        minimum_cpe_score=0.55,
    )

    print("\n" + "=" * 80)
    print("4. 서비스별 전체 분석 결과")
    print("=" * 80)
    print(json.dumps(result["services"], ensure_ascii=False, indent=2))

    print("\n" + "=" * 80)
    print("5. 3팀 전달용 최종 결과")
    print("=" * 80)

    team3_records = result.get("team3_records", [])

    if not team3_records:
        print("3팀으로 전달할 취약점 데이터가 없습니다.")
        return

    print(json.dumps(team3_records, ensure_ascii=False, indent=2))

    print("\n간단 요약")
    for index, record in enumerate(team3_records, start=1):
        print(
            f"[{index}] "
            f"{record.get('cve_id')} | "
            f"CVSS: {record.get('cvss_score')} | "
            f"등급: {record.get('severity')} | "
            f"서비스: {record.get('product')} "
            f"{record.get('version')}"
        )


if __name__ == "__main__":
    main()