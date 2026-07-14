import json
import time
from pathlib import Path

from team2_module.service_analysis_module import flatten_team1_scan_output
from team2_module.vulnerability_service import analyze_services


def print_elapsed(label: str, start_time: float) -> float:
    """단계별 소요 시간을 출력하고 초 단위 값을 반환한다."""
    elapsed = time.perf_counter() - start_time
    print(f"{label}: {elapsed:.3f}초")
    return elapsed


def main() -> None:
    total_start = time.perf_counter()

    json_path = Path(__file__).parent / "nmap_output_team1_example.json"

    # 1. JSON 읽기
    print("=" * 80)
    print("1. 팀 1 원본 JSON 읽기")
    print("=" * 80)

    step_start = time.perf_counter()

    with json_path.open("r", encoding="utf-8") as file:
        team1_output = json.load(file)

    json_load_time = print_elapsed(
        "JSON 파일 읽기 시간",
        step_start,
    )

    print(json.dumps(team1_output, ensure_ascii=False, indent=2))

    # 2. 평탄화
    print("\n" + "=" * 80)
    print("2. 팀 2 입력용 평탄화")
    print("=" * 80)

    step_start = time.perf_counter()

    normalized_services = flatten_team1_scan_output(team1_output)

    flatten_time = print_elapsed(
        "평탄화 처리 시간",
        step_start,
    )

    print(f"평탄화된 서비스 수: {len(normalized_services)}")
    print(json.dumps(normalized_services, ensure_ascii=False, indent=2))

    # 3. NVD + Web Search 분석
    print("\n" + "=" * 80)
    print("3. NVD 및 Web Search 기반 취약점 분석")
    print("=" * 80)

    step_start = time.perf_counter()

    result = analyze_services(
        normalized_services,
        use_web_search=True,
        max_cves=3,
        cpe_candidate_limit=10,
        minimum_cpe_score=0.55,
    )

    vulnerability_analysis_time = print_elapsed(
        "전체 취약점 분석 시간",
        step_start,
    )

    # 4. 서비스별 결과 출력
    print("\n" + "=" * 80)
    print("4. 서비스별 전체 분석 결과")
    print("=" * 80)

    step_start = time.perf_counter()

    print(json.dumps(result["services"], ensure_ascii=False, indent=2))

    service_output_time = print_elapsed(
        "서비스별 결과 출력 시간",
        step_start,
    )

    # 5. 3팀 전달용 결과 생성 및 출력
    print("\n" + "=" * 80)
    print("5. 3팀 전달용 최종 결과")
    print("=" * 80)

    step_start = time.perf_counter()

    team3_records = result.get("team3_records", [])

    if not team3_records:
        print("3팀으로 전달할 취약점 데이터가 없습니다.")

        team3_output_time = print_elapsed(
            "3팀 결과 처리 시간",
            step_start,
        )

        total_time = time.perf_counter() - total_start

        print("\n" + "=" * 80)
        print("6. 시간 측정 요약")
        print("=" * 80)
        print(f"JSON 파일 읽기: {json_load_time:.3f}초")
        print(f"입력 평탄화: {flatten_time:.3f}초")
        print(f"취약점 분석: {vulnerability_analysis_time:.3f}초")
        print(f"서비스 결과 출력: {service_output_time:.3f}초")
        print(f"3팀 결과 처리: {team3_output_time:.3f}초")
        print(f"전체 실행 시간: {total_time:.3f}초")
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

    team3_output_time = print_elapsed(
        "3팀 결과 처리 및 출력 시간",
        step_start,
    )

    # 6. 전체 시간 요약
    total_time = time.perf_counter() - total_start

    print("\n" + "=" * 80)
    print("6. 시간 측정 요약")
    print("=" * 80)
    print(f"JSON 파일 읽기: {json_load_time:.3f}초")
    print(f"입력 평탄화: {flatten_time:.3f}초")
    print(f"NVD + Web Search 분석: {vulnerability_analysis_time:.3f}초")
    print(f"서비스 결과 출력: {service_output_time:.3f}초")
    print(f"3팀 결과 처리 및 출력: {team3_output_time:.3f}초")
    print(f"전체 실행 시간: {total_time:.3f}초")


if __name__ == "__main__":
    main()