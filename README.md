# AI-based Vulnerability Analysis & Risk Prediction System
### AI 기반 Nmap 취약점 분석 및 위험도 예측 시스템

---

## 👥 팀원 (7명)

- **김문선** (루키즈 33기)
- **박건우** (루키즈 33기)
- **손강훈** (루키즈 33기)
- **안준엽** (루키즈 33기)
- **유경민** (루키즈 33기)
- **유석호** (루키즈 33기)
- **윤선우** (루키즈 33기)

---

# 📌 프로젝트 소개

본 프로젝트는 **Nmap 스캔 결과를 기반으로 최신 취약점(CVE)을 자동 분석하고,
머신러닝(Random Forest)을 이용하여 취약점의 위험도를 예측하는 AI 기반 침투 테스트 지원 시스템**입니다.

기존 취약점 분석은 사용자가 CVE를 직접 검색하고
CVSS 및 대응 방안을 일일이 확인해야 하는 불편함이 존재합니다.

본 프로젝트에서는 Nmap 결과만 입력하면

- 서비스 및 버전 식별
- 최신 CVE 조회
- CVSS 및 CWE 분석
- AI 기반 위험도 예측
- Streamlit Dashboard 시각화

까지 자동으로 수행할 수 있도록 구현하였습니다.

---

# 🎯 연구 목표

- Nmap 기반 취약점 자동 분석
- 최신 CVE 데이터 자동 수집
- 머신러닝 기반 위험도 예측
- 실시간 취약점 우선순위 제공
- 사용자 친화적 Dashboard 제공

---

# 📑 목차

- 프로젝트 개요
- 시스템 구조
- 주요 기능
- AI 모델
- API 활용
- 프로젝트 구조
- 설치 및 실행
- 향후 계획

---

# 🏗 시스템 구조

```
Target Host

↓

Nmap Scan

↓

Service Parsing

↓

Vulners API
        ↓
NVD API

↓

Hybrid Vulnerability Analysis

↓

Random Forest Risk Prediction

↓

Streamlit Dashboard
```

---

# 🔍 주요 기능

## 1. Nmap 스캔 결과 분석

- 포트 및 서비스 정보 추출
- 제품(Product) 및 Version 분석
- JSON 형태로 변환

---

## 2. 최신 취약점 조회

### Vulners API

- 제품명 기반 CVE 검색
- 버전 기반 취약점 조회
- 빠른 Threat Intelligence 제공

### NVD API

- 공식 CVE 정보 조회
- CVSS / CWE 정보 제공
- CPE 기반 취약점 검증

### Hybrid 구조

- Vulners API를 이용하여 후보 취약점 조회
- NVD API를 이용하여 공식 정보를 검증 및 보완
- 중복 CVE 제거 및 정보 병합

---

## 3. AI 기반 위험도 예측

Random Forest 모델을 활용하여

- CVSS
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
- CWE

등의 Feature를 기반으로 위험도를 예측합니다.

---

## 4. Dashboard

- 취약점 목록 출력
- 위험도 시각화
- CVSS 정보 표시
- PDF 보고서 생성

---

# 🤖 머신러닝 모델

프로젝트에서는 다음 모델을 비교하였습니다.

- Decision Tree
- Logistic Regression
- Random Forest

### 평가 지표

- Accuracy
- Precision
- Recall
- F1-score
- Weighted F1-score
- Confusion Matrix

비교 결과 Random Forest가 가장 우수한 성능을 보여 최종 모델로 선정하였습니다.

---

# 🌐 사용 API

## Vulners API

- 제품 기반 취약점 조회
- Threat Intelligence
- Exploit 정보 제공

## NVD API

- 공식 CVE Database
- CVSS
- CWE
- CPE 정보 제공

---

# 📂 프로젝트 구조

```
project/

├── app.py
├── team1/
│
├── team2/
│   ├── nvd_module.py
│   ├── vulners_module.py
│   ├── hybrid_provider.py
│   ├── service_analysis_module.py
│   ├── vulnerability_service.py
│   └── schemas.py
│
├── team3/
│
├── dashboard/
│
└── report/
```

---

# ⚙ 설치 및 실행

## 개발 환경

- Python 3.12
- Streamlit
- Scikit-learn
- Nmap
- Requests

### 설치

```bash
pip install -r requirements.txt
```

### 실행

```bash
streamlit run app.py
```

---

# 🚧 향후 계획

- CVE 데이터 자동 업데이트
- EPSS 및 KEV 연동
- Exploit-DB 연동
- LLM 기반 대응 방안 생성
- 실시간 스캔 자동화

---

# 📚 참고 자료

- NVD API
- Vulners API
- Nmap
- CVSS v4.0
- MITRE CVE
- MITRE CWE

---