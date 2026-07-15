# 취약점 찾아조 챗봇 — Vulners API 버전

## 최종 폴더 구성

```text
프로젝트폴더/
├─ .venv/
├─ .gitignore
├─ .env
├─ env_vulners.example
├─ chatbot1_vulners.py
├─ team4_output.json
├─ team4_output.txt
├─ requirements_vulners.txt
└─ README_vulners.md
```

`env_vulners.example` 파일을 프로젝트에 넣은 뒤 `.env`로 복사해서 사용합니다.

## 환경변수

```env
OPENAI_API_KEY=OpenAI_API_Key
OPENAI_MODEL=gpt-4.1-mini

VULNERS_API_KEY=Vulners_API_Key
VULNERS_BASE_URL=https://vulners.com/api/v3
```

- VULNERS_API_KEY: 최신 CVE와 취약점 검색
- OPENAI_API_KEY: 질문 해석, Function Calling, 자연어 답변 생성

## 설치

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements_vulners.txt
```

## 실행

```powershell
streamlit run chatbot1_vulners.py
```

## Function Calling 400 오류 방지

모든 함수 스키마에 다음을 적용했습니다.

```python
"strict": True,
"additionalProperties": False
```

`calculate_risk`의 모든 속성을 required에 포함했습니다.

```python
"required": [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "cvss_score",
]
```
