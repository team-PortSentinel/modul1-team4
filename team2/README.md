# Team 2 Module

## 역할

1. 팀 1 Nmap 파싱 결과 정규화
2. NVD CPE/CVE API 실시간 조회
3. CVE, CVSS, CWE, 설명, 영향 버전 추출
4. 현재 서비스 버전의 취약점 적용 여부 판별
5. 상위 CVE를 OpenAI Web Search로 보강
6. 팀 3 모델 입력 컬럼으로 평탄화

## 사용 예시

```python
from team2_security import analyze_services

team1_output = [
    {
        "host": "192.168.1.10",
        "port": 80,
        "status": "open",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.41",
    }
]

result = analyze_services(
    team1_output,
    use_web_search=False,  # OpenAI 키 설정 후 True
)

print(result["team3_records"])
```

## 팀 3 출력 핵심 컬럼

- cve_id
- cvss_score
- severity
- attack_vector
- attack_complexity
- privileges_required
- user_interaction
- cwe
- description

서비스 추적을 위해 host, port, service, product, version, applicability도 함께 포함됩니다.
