"""
NVD API로 CVE 취약점 데이터를 대량(약 10,000건) 수집하여 CSV로 저장하는 코드 (v3)
- 팀2 산출물: 팀3에게 넘길 대규모 학습 데이터셋(cve_dataset.csv)
- [핵심] 최신 CVE부터 받아서 CVSS v3 점수가 있는 것만 모음
  (옛날 CVE는 CVSS v3 점수가 없어서 걸러지므로, 최신부터 받아야 효율적)
"""

import requests
import pandas as pd
import time

# ============================================================
# 설정
# ============================================================
목표_개수 = 10000          # CVSS 점수 있는 데이터 기준 목표

# NVD API 키 (있으면 훨씬 빠름). 없으면 None 그대로.
# 발급(무료): https://nvd.nist.gov/developers/request-an-api-key
API_KEY = None


# ============================================================
# 1. NVD API로 CVE 데이터 받아오기 (최신순, 페이지 단위)
# ============================================================
def CVE_수집(start_index, 개수=2000):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 개수,
        "startIndex": start_index
    }

    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY

    try:
        response = requests.get(url, params=params, headers=headers, timeout=60)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"  요청 실패 (상태코드: {response.status_code}) - 잠시 후 재시도")
            return "retry"     # 재시도 신호
    except Exception as e:
        print(f"  에러: {e} - 잠시 후 재시도")
        return "retry"


# ============================================================
# 2. JSON에서 필요한 정보 추출 (CVSS v3 있는 것만)
# ============================================================
def CVE정보_추출(응답_json):
    결과목록 = []

    for item in 응답_json.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        # CVSS v3 정보 (없으면 이 CVE는 건너뜀)
        metrics = cve.get("metrics", {})
        d = None
        if "cvssMetricV31" in metrics:
            d = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            d = metrics["cvssMetricV30"][0]["cvssData"]

        if d is None:          # CVSS v3 점수 없으면 학습에 못 쓰므로 제외
            continue

        # 설명 (영어)
        설명 = ""
        for desc in cve.get("descriptions", []):
            if desc["lang"] == "en":
                설명 = desc["value"]
                break

        # CWE (취약점 유형)
        cwe = None
        for w in cve.get("weaknesses", []):
            for wd in w.get("description", []):
                if wd["value"].startswith("CWE-"):
                    cwe = wd["value"]
                    break
            if cwe:
                break

        결과목록.append({
            "cve_id": cve_id,
            "cvss_score": d.get("baseScore"),
            "severity": d.get("baseSeverity"),
            "attack_vector": d.get("attackVector"),
            "attack_complexity": d.get("attackComplexity"),
            "privileges_required": d.get("privilegesRequired"),
            "user_interaction": d.get("userInteraction"),
            "cwe": cwe,
            "description": 설명
        })

    return 결과목록


# ============================================================
# 3. 목표 개수 채울 때까지 최신순으로 수집 → CSV 저장
# ============================================================
def 데이터셋_생성():
    # 먼저 전체 CVE 개수를 알아내서, 최신(뒤쪽)부터 받기 위한 시작점 계산
    첫응답 = None
    while 첫응답 is None or 첫응답 == "retry":
        첫응답 = CVE_수집(0, 개수=1)
        if 첫응답 == "retry":
            time.sleep(10)

    전체CVE수 = 첫응답.get("totalResults", 0)
    print(f"NVD 전체 CVE 수: {전체CVE수}개")
    print(f"목표: CVSS 있는 것 {목표_개수}개 (최신순 수집)\n")

    전체데이터 = []
    페이지크기 = 2000
    # 최신 CVE는 뒤쪽 인덱스에 있으므로, 끝에서부터 거슬러 올라감
    start_index = max(0, 전체CVE수 - 페이지크기)

    대기시간 = 1 if API_KEY else 6

    while len(전체데이터) < 목표_개수 and start_index >= 0:
        print(f"인덱스 {start_index}부터 수집 중... (현재 CVSS 유효 {len(전체데이터)}개)")
        응답 = CVE_수집(start_index, 개수=페이지크기)

        if 응답 == "retry":       # 일시 오류면 잠깐 쉬고 재시도
            time.sleep(10)
            continue

        추출결과 = CVE정보_추출(응답)   # CVSS 있는 것만 추림
        전체데이터.extend(추출결과)

        start_index -= 페이지크기      # 더 이전 구간으로 이동
        time.sleep(대기시간)

    # 정리
    df = pd.DataFrame(전체데이터)
    df = df.drop_duplicates(subset="cve_id")
    df = df.head(목표_개수)

    df.to_csv("cve_dataset.csv", index=False, encoding="utf-8-sig")

    print(f"\n최종 데이터셋 저장 완료: 총 {len(df)}개")
    print(df.head())
    print("\nseverity 분포:")
    print(df["severity"].value_counts())

    return df


# ============================================================
# 실행
# ============================================================
if __name__ == "__main__":
    데이터셋_생성()


'''결과 해석
- [수정 포인트] 이전 버전은 인덱스 0(=가장 오래된 1999년 CVE)부터 받아서
  CVSS v3 점수가 없는 옛날 데이터가 대부분이라 대량 삭제됐음(→ 193개만 남음)
- 이번 버전은 전체 개수를 먼저 파악한 뒤 "최신 CVE부터" 거슬러 올라가며 수집
  → CVSS v3(2015년 이후 도입) 점수가 있는 데이터가 대부분이라 효율적으로 10,000개 확보
- CVSS v3 없는 CVE는 추출 단계에서 건너뛰므로, 받은 데이터가 거의 그대로 유효
- 특징: cvss_score, severity, attack_vector, attack_complexity,
        privileges_required, user_interaction, cwe

- 속도: 키 없으면 6초 간격 → 10,000개면 여러 페이지라 몇 분 소요
        키 있으면 1초 간격 → 훨씬 빠름
- 일시적 오류(429/503)는 자동으로 10초 쉬고 재시도하도록 처리함
'''