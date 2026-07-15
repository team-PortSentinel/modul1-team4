from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent

sys.path.insert(
    0,
    str(PROJECT_ROOT / "team2"),
)

load_dotenv()

from team2.team2_module.service_analysis_module import (
    flatten_team1_scan_output,
)
from team2.team2_module.vulnerability_service import (
    analyze_services,
)
from team3.inference import predict_priority


def main() -> None:
    total_start = time.perf_counter()

    input_path = (
        PROJECT_ROOT
        / "team2"
        / "nmap_output_team1_example.json"
    )

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        team1_output = json.load(file)

    normalized_services = (
        flatten_team1_scan_output(
            team1_output
        )
    )

    print(
        f"1팀 서비스 수: "
        f"{len(normalized_services)}"
    )

    team2_start = time.perf_counter()

    team2_result = analyze_services(
        normalized_services,
        max_cves=5,
    )

    team2_time = (
        time.perf_counter()
        - team2_start
    )

    team3_input = team2_result.get(
        "team3_records",
        [],
    )

    print(
        f"2팀 결과 수: "
        f"{len(team3_input)}"
    )

    if not team3_input:
        raise RuntimeError(
            "3팀으로 전달할 취약점 데이터가 없습니다."
        )

    team3_start = time.perf_counter()

    priority_result = predict_priority(
        team3_input
    )

    team3_time = (
        time.perf_counter()
        - team3_start
    )

    print(
        f"3팀 결과 수: "
        f"{len(priority_result)}"
    )

    print("\n우선순위 결과")

    for record in priority_result[:10]:
        print(
            f"{record.get('priority_rank')}위 | "
            f"{record.get('cve_id')} | "
            f"{record.get('product')} "
            f"{record.get('version')} | "
            f"CVSS={record.get('cvss_score')} | "
            f"예측={record.get('predicted_severity')} | "
            f"점수={record.get('priority_score')} | "
            f"{record.get('response_priority')}"
        )

    output_path = (
        PROJECT_ROOT
        / "team2_team3_result.json"
    )

    output_path.write_text(
        json.dumps(
            priority_result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    total_time = (
        time.perf_counter()
        - total_start
    )

    print("\n시간")
    print(f"2팀 분석: {team2_time:.3f}초")
    print(f"3팀 추론: {team3_time:.3f}초")
    print(f"전체: {total_time:.3f}초")
    print(f"저장 위치: {output_path}")


if __name__ == "__main__":
    main()