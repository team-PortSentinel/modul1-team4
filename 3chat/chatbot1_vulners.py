# ==========================================================
# chatbot1_vulners.py
#
# 취약점 찾아조 - Vulners API 기반 보안 챗봇
#
# 주요 기능
# 1. Vulners API를 이용한 최신 CVE/취약점 조회
# 2. PromptBuilder를 이용한 Nmap Parser JSON 분석
# 3. OpenAI Function Calling을 이용한 위험도 재계산
# 4. team4_output.json 로컬 위험도 결과 조회 및 우선순위 정렬
# 5. 이전 대화 결과를 기억하는 Streamlit 챗봇
#
# 주의
# - Vulners API: 취약점 데이터 검색 담당
# - OpenAI API: 질문 해석, 함수 호출, 최종 답변 생성 담당
# ==========================================================

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import requests
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI


# ----------------------------------------------------------
# 1. 기본 경로 및 환경변수
# ----------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

RISK_JSON_PATH = BASE_DIR / "team4_output.json"
RISK_TEXT_PATH = BASE_DIR / "team4_output.txt"

load_dotenv(ENV_PATH, override=True)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "").strip()
VULNERS_BASE_URL = os.getenv(
    "VULNERS_BASE_URL",
    "https://vulners.com/api/v3",
).rstrip("/")

REQUEST_TIMEOUT = 30

st.set_page_config(
    page_title="취약점 찾아조 AI 챗봇",
    page_icon="🛡️",
    layout="wide",
)


# ----------------------------------------------------------
# 2. Nmap Parser 결과 → 분석 프롬프트
#    사용자가 전달한 PromptBuilder 구조를 통합·보완
# ----------------------------------------------------------
class PromptBuilder:
    """Parser가 정리한 Nmap 결과를 AI 분석용 프롬프트로 변환한다."""

    def __init__(self, parsed_data: dict[str, Any]):
        self.parsed_data = parsed_data

    @staticmethod
    def _safe(value: Any, default: str = "정보 없음") -> str:
        if value is None or value == "":
            return default
        return str(value)

    def build_prompt(self) -> str:
        hosts = self.parsed_data.get("hosts", [])

        prompt = """
당신은 침투테스트 전문가이자 보안 컨설턴트입니다.

아래 Nmap 스캔 결과를 분석하세요.

중요:
- 서비스명, 제품명, 버전을 근거로 취약점을 확인합니다.
- 최신 CVE 정보는 Vulners API 검색 결과를 사용합니다.
- 검색으로 확인되지 않은 CVE는 만들어내지 않습니다.
- 버전 정보가 불명확하면 취약하다고 단정하지 말고 추가 확인 필요라고 표시합니다.

다음 형식으로 답변하세요.

==============================

1. 시스템 정보

2. 서비스별 취약점

3. 관련 CVE

4. CVSS 점수

5. 위험도
(CRITICAL / HIGH / MEDIUM / LOW)

6. 공격 가능성

7. 공개 Exploit 존재 여부

8. 대응 방안

9. 출처

==============================
"""

        if not hosts:
            return prompt + "\n분석할 Host 정보가 없습니다."

        for host in hosts:
            os_data = host.get("os") or {}

            prompt += (
                f"\nHost IP : {self._safe(host.get('ip'))}\n"
                f"Hostname : {self._safe(host.get('hostname'))}\n"
                f"Status : {self._safe(host.get('status'))}\n"
                f"OS : {self._safe(os_data.get('name'))}\n"
                "\n========== Open Ports ==========\n"
            )

            ports = host.get("ports") or []

            if not ports:
                prompt += "열린 포트 정보 없음\n"

            for port in ports:
                prompt += (
                    f"\nPort : {self._safe(port.get('port'))}/"
                    f"{self._safe(port.get('protocol'))}\n"
                    f"State : {self._safe(port.get('state'))}\n"
                    f"Service : {self._safe(port.get('service'))}\n"
                    f"Product : {self._safe(port.get('product'))}\n"
                    f"Version : {self._safe(port.get('version'))}\n"
                    f"Extra Info : {self._safe(port.get('extrainfo'))}\n"
                    "----------------------------------------\n"
                )

        prompt += """
위 서비스들의 취약점, CVE 번호, CVSS 점수, 위험도,
공개 Exploit 존재 여부, 공격 가능성, 대응 방안을
Vulners API 검색 결과를 기준으로 분석해주세요.
"""

        return prompt


# ----------------------------------------------------------
# 3. 로컬 위험도 결과 로드
# ----------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_risk_records() -> list[dict[str, Any]]:
    if not RISK_JSON_PATH.exists():
        return []

    try:
        parsed = json.loads(RISK_JSON_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    return parsed if isinstance(parsed, list) else []


RISK_RECORDS = load_risk_records()

RISK_INDEX = {
    str(record.get("cve_id", "")).upper(): record
    for record in RISK_RECORDS
    if record.get("cve_id")
}


# ----------------------------------------------------------
# 4. Vulners API
# ----------------------------------------------------------
def _require_vulners_key() -> None:
    if not VULNERS_API_KEY:
        raise ValueError(
            ".env에서 VULNERS_API_KEY를 찾지 못했습니다. "
            "Vulners의 API Keys 화면에서 키를 발급한 뒤 입력하세요."
        )


def _extract_vulners_documents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Vulners API 응답 버전에 따른 구조 차이를 최대한 안전하게 처리한다.
    일반적으로 data.search 안에 검색 결과가 들어온다.
    """
    data = payload.get("data")

    if isinstance(data, dict):
        candidates = (
            data.get("search")
            or data.get("documents")
            or data.get("results")
            or []
        )
    else:
        candidates = (
            payload.get("search")
            or payload.get("documents")
            or payload.get("results")
            or []
        )

    if not isinstance(candidates, list):
        return []

    normalized: list[dict[str, Any]] = []

    for item in candidates:
        if not isinstance(item, dict):
            continue

        source = item.get("_source")

        if isinstance(source, dict):
            merged = {**source}

            if "_id" not in merged and item.get("_id"):
                merged["_id"] = item["_id"]

            normalized.append(merged)
        else:
            normalized.append(item)

    return normalized


def _normalize_vulners_record(record: dict[str, Any]) -> dict[str, Any]:
    cve_list = record.get("cvelist") or record.get("cveList") or []

    if isinstance(cve_list, str):
        cve_list = [cve_list]

    cvss_data = record.get("cvss") or {}
    cvss3_data = record.get("cvss3") or record.get("cvssV3") or {}

    cvss_score = (
        cvss3_data.get("cvssV3", {}).get("baseScore")
        if isinstance(cvss3_data.get("cvssV3"), dict)
        else None
    )

    if cvss_score is None:
        cvss_score = cvss3_data.get("score")

    if cvss_score is None:
        cvss_score = cvss_data.get("score")

    bulletin_id = (
        record.get("id")
        or record.get("_id")
        or record.get("bulletinFamily")
        or ""
    )

    href = record.get("href")

    if not href and bulletin_id:
        href = f"https://vulners.com/{record.get('type', 'cve')}/{bulletin_id}"

    return {
        "id": bulletin_id,
        "title": record.get("title") or record.get("description", "")[:120],
        "description": record.get("description") or record.get("shortDescription"),
        "cve_ids": cve_list,
        "cvss_score": cvss_score,
        "published": record.get("published"),
        "modified": record.get("modified"),
        "type": record.get("type"),
        "bulletin_family": record.get("bulletinFamily"),
        "href": href,
        "source": "Vulners API",
    }


def vulners_search(query: str, limit: int = 8) -> dict[str, Any]:
    """Vulners Lucene 검색 API를 호출한다."""
    _require_vulners_key()

    clean_query = query.strip()

    if not clean_query:
        raise ValueError("검색어가 비어 있습니다.")

    safe_limit = max(1, min(int(limit), 20))
    url = f"{VULNERS_BASE_URL}/search/lucene/"

    body = {
        "query": clean_query,
        "size": safe_limit,
        "skip": 0,
        "fields": [
            "id",
            "title",
            "description",
            "published",
            "modified",
            "cvss",
            "cvelist",
            "href",
            "type",
            "bulletinFamily",
        ],
    }

    response = requests.post(
        url,
        json=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "FindVulnerabilityChatbot/1.0",
            "X-Api-Key": VULNERS_API_KEY,
        },
        timeout=REQUEST_TIMEOUT,
    )
    print("=" * 60)
    print("Status :", response.status_code)
    print(response.text)
    print("=" * 60)
    if response.status_code == 401:
        raise RuntimeError(
            "Vulners API 인증에 실패했습니다. VULNERS_API_KEY를 확인하세요."
        )

    if response.status_code == 403:
        raise RuntimeError(
            "Vulners API 접근이 거부되었습니다. 키 권한 또는 요금제를 확인하세요."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "Vulners API 요청 한도를 초과했습니다. 잠시 후 다시 시도하세요."
        )

    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        raise RuntimeError(
            f"Vulners API 호출 실패: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        ) from error

    try:
        payload = response.json()
    except ValueError as error:
        raise RuntimeError("Vulners API가 JSON이 아닌 응답을 반환했습니다.") from error

    raw_documents = _extract_vulners_documents(payload)
    documents = [_normalize_vulners_record(item) for item in raw_documents]

    return {
        "query": clean_query,
        "count": len(documents),
        "results": documents,
    }


def search_cve_by_id(cve_id: str) -> dict[str, Any]:
    normalized = cve_id.upper().strip()

    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        return {
            "error": "올바른 CVE 형식이 아닙니다.",
            "example": "CVE-2021-41773",
        }

    return vulners_search(f'id:"{normalized}" OR cvelist:"{normalized}"', limit=10)


def search_vulnerabilities(
    product: str,
    version: str = "",
    service: str = "",
    limit: int = 8,
) -> dict[str, Any]:
    product = product.strip()
    version = version.strip()
    service = service.strip()

    terms = [term for term in [product, version, service] if term]

    if not terms:
        raise ValueError("제품명, 버전 또는 서비스명 중 하나는 필요합니다.")

    # Lucene 특수문자에 의한 400을 줄이기 위해 따옴표 검색 사용
    quoted_terms = [f'"{term.replace(chr(34), "")}"' for term in terms]
    query = " AND ".join(quoted_terms)

    return vulners_search(query=query, limit=limit)


# ----------------------------------------------------------
# 5. 프로젝트 내부 위험도 계산
#    공식 CVSS 계산기가 아닌 조치 우선순위 점수
# ----------------------------------------------------------
def calculate_risk(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    cvss_score: float,
) -> dict[str, Any]:
    attack_vector = attack_vector.upper().strip()
    attack_complexity = attack_complexity.upper().strip()
    privileges_required = privileges_required.upper().strip()
    user_interaction = user_interaction.upper().strip()

    vector_scores = {
        "NETWORK": 30,
        "ADJACENT": 22,
        "LOCAL": 12,
        "PHYSICAL": 5,
    }
    complexity_scores = {"LOW": 20, "HIGH": 8}
    privilege_scores = {"NONE": 25, "LOW": 15, "HIGH": 5}
    interaction_scores = {"NONE": 15, "REQUIRED": 5}

    normalized_cvss = max(0.0, min(float(cvss_score), 10.0))

    score = (
        vector_scores.get(attack_vector, 0)
        + complexity_scores.get(attack_complexity, 0)
        + privilege_scores.get(privileges_required, 0)
        + interaction_scores.get(user_interaction, 0)
        + normalized_cvss
    )

    score = round(min(score, 100.0), 1)

    if score >= 85:
        risk_level = "CRITICAL"
        response_priority = "긴급 대응"
    elif score >= 65:
        risk_level = "HIGH"
        response_priority = "우선 대응"
    elif score >= 40:
        risk_level = "MEDIUM"
        response_priority = "계획 대응"
    else:
        risk_level = "LOW"
        response_priority = "모니터링"

    return {
        "priority_score": score,
        "risk_level": risk_level,
        "response_priority": response_priority,
        "inputs": {
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "cvss_score": normalized_cvss,
        },
        "notice": (
            "이 점수는 팀 프로젝트의 조치 우선순위용 내부 점수이며 "
            "공식 CVSS 점수와는 구분해야 합니다."
        ),
    }


def lookup_local_cve(cve_id: str) -> dict[str, Any]:
    normalized = cve_id.upper().strip()
    record = RISK_INDEX.get(normalized)

    if record:
        return {"found": True, "record": record}

    return {
        "found": False,
        "cve_id": normalized,
        "message": "team4_output.json에서 해당 CVE를 찾지 못했습니다.",
    }


def rank_vulnerabilities(cve_ids: list[str]) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    missing: list[str] = []

    for cve_id in cve_ids:
        normalized = cve_id.upper().strip()
        record = RISK_INDEX.get(normalized)

        if record:
            found.append(record)
        else:
            missing.append(normalized)

    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            float(item.get("priority_score") or 0),
            float(item.get("cvss_score") or 0),
            item.get("attack_vector") == "NETWORK",
            item.get("attack_complexity") == "LOW",
            item.get("privileges_required") == "NONE",
            item.get("user_interaction") == "NONE",
        )

    ranked = sorted(found, key=sort_key, reverse=True)

    compact_results = []

    for index, item in enumerate(ranked, start=1):
        compact_results.append(
            {
                "rank": index,
                "cve_id": item.get("cve_id"),
                "priority_score": item.get("priority_score"),
                "cvss_score": item.get("cvss_score"),
                "severity": item.get("severity"),
                "predicted_severity": item.get("predicted_severity"),
                "response_priority": item.get("response_priority"),
                "attack_vector": item.get("attack_vector"),
                "attack_complexity": item.get("attack_complexity"),
                "privileges_required": item.get("privileges_required"),
                "user_interaction": item.get("user_interaction"),
                "description": item.get("description"),
            }
        )

    return {
        "ranked": compact_results,
        "missing": missing,
        "tie_break_notice": (
            "점수가 같다면 외부 노출 여부, 실제 악용 여부, 자산 중요도, "
            "패치 제공 여부와 업무 영향도를 추가로 비교해야 합니다."
        ),
    }


# ----------------------------------------------------------
# 6. OpenAI Function Calling 도구 정의
#
# 400 오류 방지를 위해:
# - strict=True
# - additionalProperties=False
# - properties에 선언한 필드를 required에 모두 포함
# - calculate_risk의 cvss_score도 required에 포함
# ----------------------------------------------------------
TOOLS = [
    {
        "type": "function",
        "name": "search_cve_by_id",
        "description": "Vulners API에서 특정 CVE 번호의 최신 취약점 정보를 조회한다.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "조회할 CVE 번호. 예: CVE-2021-41773",
                }
            },
            "required": ["cve_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "search_vulnerabilities",
        "description": (
            "Vulners API에서 제품명, 버전 및 서비스명을 이용해 "
            "관련 취약점과 CVE를 검색한다."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "product": {
                    "type": "string",
                    "description": "제품명. 모르면 빈 문자열",
                },
                "version": {
                    "type": "string",
                    "description": "제품 버전. 모르면 빈 문자열",
                },
                "service": {
                    "type": "string",
                    "description": "서비스명. 모르면 빈 문자열",
                },
                "limit": {
                    "type": "integer",
                    "description": "검색 결과 개수. 일반적으로 5~10",
                },
            },
            "required": [
                "product",
                "version",
                "service",
                "limit",
            ],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "calculate_risk",
        "description": (
            "공격 경로, 공격 복잡도, 필요 권한, 사용자 상호작용과 "
            "CVSS 점수로 프로젝트 내부 조치 우선순위 점수를 계산한다."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "attack_vector": {
                    "type": "string",
                    "enum": ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"],
                },
                "attack_complexity": {
                    "type": "string",
                    "enum": ["LOW", "HIGH"],
                },
                "privileges_required": {
                    "type": "string",
                    "enum": ["NONE", "LOW", "HIGH"],
                },
                "user_interaction": {
                    "type": "string",
                    "enum": ["NONE", "REQUIRED"],
                },
                "cvss_score": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                },
            },
            "required": [
                "attack_vector",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "cvss_score",
            ],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "lookup_local_cve",
        "description": "team4_output.json에서 특정 CVE의 예측 위험도 결과를 조회한다.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "조회할 CVE 번호",
                }
            },
            "required": ["cve_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "rank_vulnerabilities",
        "description": "여러 CVE를 로컬 위험도 점수 기준으로 정렬한다.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "우선순위를 비교할 CVE 번호 목록",
                }
            },
            "required": ["cve_ids"],
            "additionalProperties": False,
        },
    },
]

FUNCTION_MAP = {
    "search_cve_by_id": search_cve_by_id,
    "search_vulnerabilities": search_vulnerabilities,
    "calculate_risk": calculate_risk,
    "lookup_local_cve": lookup_local_cve,
    "rank_vulnerabilities": rank_vulnerabilities,
}


# ----------------------------------------------------------
# 7. 시스템 프롬프트
# ----------------------------------------------------------
SYSTEM_PROMPT = """
당신은 '취약점 찾아조' 프로젝트의 보안 분석 챗봇입니다.

도구 사용 기준:

1. 단순 조회
- 특정 CVE 질문: search_cve_by_id
- 제품/버전 취약점 질문: search_vulnerabilities

2. 재계산
- 공격 경로, 복잡도, 권한, 사용자 상호작용, CVSS를 이용한
  위험도 계산: calculate_risk

3. 로컬 머신러닝 결과
- team4_output.json의 특정 CVE 확인: lookup_local_cve
- 여러 CVE의 우선순위 비교: rank_vulnerabilities

4. 복합 질문
- 제품 취약점을 Vulners API로 검색한 뒤 위험도 계산이 필요하면
  검색 결과를 확인하고 calculate_risk도 호출합니다.

5. 기존 결과 설명
- '1순위가 왜 긴급 대응이야?', '방금 결과 요약해줘',
  '오늘 안에 막아야 하는 건 몇 개야?'처럼 직전 결과를 설명하는 질문은
  대화 기록을 먼저 참고하고 불필요하게 다시 검색하지 않습니다.

답변 원칙:

- 한국어로 답변합니다.
- Vulners 검색 결과에 없는 CVE나 세부 내용을 만들어내지 않습니다.
- CVSS 점수와 프로젝트 내부 priority_score를 명확히 구분합니다.
- 제품명이나 버전이 불명확하면 단정하지 않습니다.
- 공격 코드나 실제 침해 절차보다 방어, 조치 우선순위, 패치 및 완화 방안을 중심으로 답합니다.
- Vulners 결과에 href가 있으면 출처로 표시합니다.
"""


# ----------------------------------------------------------
# 8. OpenAI Responses API + Function Calling
# ----------------------------------------------------------
def get_openai_client() -> OpenAI:
    if not OPENAI_API_KEY:
        raise ValueError(
            ".env에서 OPENAI_API_KEY를 찾지 못했습니다. "
            "Vulners API는 취약점 검색용이며, 자연어 챗봇 응답에는 "
            "OpenAI API 키가 별도로 필요합니다."
        )

    return OpenAI(api_key=OPENAI_API_KEY)


def build_conversation_input(
    history: list[dict[str, str]],
    user_question: str,
    nmap_prompt: str,
) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT}
    ]

    if nmap_prompt:
        messages.append(
            {
                "role": "system",
                "content": (
                    "다음은 현재 업로드된 Nmap Parser 분석 문맥입니다. "
                    "포트스캔 질문에 사용하세요.\n\n"
                    + nmap_prompt
                ),
            }
        )

    for message in history[-10:]:
        role = message.get("role")
        content = message.get("content")

        if role in {"user", "assistant"} and content:
            messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": user_question})
    return messages


def call_function(name: str, arguments_text: str) -> dict[str, Any]:
    function = FUNCTION_MAP.get(name)

    if function is None:
        return {"error": f"지원하지 않는 함수입니다: {name}"}

    try:
        arguments = json.loads(arguments_text or "{}")
    except json.JSONDecodeError:
        return {"error": "함수 인자를 JSON으로 해석하지 못했습니다."}

    try:
        return function(**arguments)
    except Exception as error:
        return {"error": str(error)}


def run_chatbot(
    user_question: str,
    history: list[dict[str, str]],
    nmap_prompt: str,
) -> str:
    client = get_openai_client()

    input_messages = build_conversation_input(
        history=history,
        user_question=user_question,
        nmap_prompt=nmap_prompt,
    )

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=input_messages,
        tools=TOOLS,
        tool_choice="auto",
    )

    # 한 번의 응답에서 여러 함수가 호출될 수 있으므로 모두 처리
    tool_outputs: list[dict[str, Any]] = []

    for item in response.output:
        if item.type != "function_call":
            continue

        result = call_function(
            name=item.name,
            arguments_text=item.arguments,
        )

        tool_outputs.append(
            {
                "type": "function_call_output",
                "call_id": item.call_id,
                "output": json.dumps(result, ensure_ascii=False),
            }
        )

    # 함수 호출이 없다면 바로 자연어 답변 반환
    if not tool_outputs:
        return response.output_text or "응답 내용이 없습니다."

    # 함수 결과를 같은 응답 흐름에 다시 전달
    final_response = client.responses.create(
        model=OPENAI_MODEL,
        previous_response_id=response.id,
        input=tool_outputs,
        tools=TOOLS,
    )

    return final_response.output_text or "최종 응답 내용이 없습니다."


# ----------------------------------------------------------
# 9. 업로드 JSON 처리
# ----------------------------------------------------------
def parse_uploaded_json(uploaded_file: Any) -> dict[str, Any]:
    raw_text = uploaded_file.getvalue().decode("utf-8-sig")
    parsed = json.loads(raw_text)

    if not isinstance(parsed, dict):
        raise ValueError("JSON 최상위 구조는 객체여야 합니다.")

    if "hosts" not in parsed or not isinstance(parsed["hosts"], list):
        raise ValueError("JSON 최상위 객체에 hosts 배열이 필요합니다.")

    return parsed


# ----------------------------------------------------------
# 10. Streamlit UI
# ----------------------------------------------------------
st.title("🛡️ 취약점 찾아조 AI 챗봇")
st.caption("Vulners API · OpenAI Function Calling · Nmap Parser · ML 위험도 결과")

if "messages" not in st.session_state:
    st.session_state.messages = []

if "nmap_prompt" not in st.session_state:
    st.session_state.nmap_prompt = ""


with st.sidebar:
    st.header("ℹ️ Information")

    st.write(
        "Vulners API로 최신 CVE를 조회하고, Function Calling으로 "
        "위험도 계산과 우선순위 정렬을 수행합니다."
    )

    st.divider()

    st.subheader("연결 상태")

    if VULNERS_API_KEY:
        st.success("VULNERS_API_KEY 로드됨")
    else:
        st.error("VULNERS_API_KEY 없음")

    if OPENAI_API_KEY:
        st.success("OPENAI_API_KEY 로드됨")
    else:
        st.error("OPENAI_API_KEY 없음")

    st.caption(f"OpenAI 모델: {OPENAI_MODEL}")

    st.divider()

    st.subheader("로컬 결과")

    st.write(f"위험도 레코드: {len(RISK_RECORDS):,}개")
    st.write(f"team4_output.json: {'정상' if RISK_JSON_PATH.exists() else '없음'}")
    st.write(f"team4_output.txt: {'정상' if RISK_TEXT_PATH.exists() else '없음'}")

    st.divider()

    uploaded_json = st.file_uploader(
        "Nmap Parser 결과 JSON 업로드",
        type=["json"],
        help="최상위에 hosts 배열이 있는 Parser 결과 JSON",
    )

    if st.button("대화 초기화", use_container_width=True):
        st.session_state.messages = []
        st.session_state.nmap_prompt = ""
        st.rerun()


if uploaded_json is not None:
    try:
        parsed_data = parse_uploaded_json(uploaded_json)
        st.session_state.nmap_prompt = PromptBuilder(parsed_data).build_prompt()

        st.success("Nmap Parser 결과를 챗봇 문맥에 적용했습니다.")

        with st.expander("생성된 Nmap 분석 프롬프트"):
            st.code(st.session_state.nmap_prompt)

    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        st.error(f"Nmap JSON 처리 실패: {error}")


with st.expander("💡 질문 예시"):
    st.markdown(
        """
- `Apache 2.4.49 취약점 있어?`
- `CVE-2021-41773이 뭐야?`
- `공격 경로 NETWORK, 복잡도 LOW, 권한 NONE, 상호작용 NONE, CVSS 9.8이면 위험도 어때?`
- `CVE-2026-50746, CVE-2026-56004, CVE-2026-13768 중 뭐부터 조치해야 해?`
- `1순위가 왜 긴급 대응이야?`
- `방금 나온 결과 요약해줘`
- `MySQL 5.7 취약점 찾아서 위험도까지 알려줘`
- `업로드한 포트스캔 결과를 보고 우선순위를 매겨줘`
"""
    )


for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])


user_question = st.chat_input(
    "취약점, CVE 또는 업로드한 포트스캔 결과에 대해 질문하세요."
)

if user_question:
    with st.chat_message("user"):
        st.markdown(user_question)

    previous_messages = st.session_state.messages.copy()

    st.session_state.messages.append(
        {"role": "user", "content": user_question}
    )

    try:
        with st.chat_message("assistant"):
            with st.spinner("Vulners API와 위험도 모델을 이용해 분석 중입니다..."):
                answer = run_chatbot(
                    user_question=user_question,
                    history=previous_messages,
                    nmap_prompt=st.session_state.nmap_prompt,
                )

                st.markdown(answer)

        st.session_state.messages.append(
            {"role": "assistant", "content": answer}
        )

    except Exception as error:
        error_text = str(error)

        if "401" in error_text or "invalid_api_key" in error_text.lower():
            st.error(
                "API 인증에 실패했습니다. OPENAI_API_KEY 또는 "
                "VULNERS_API_KEY가 올바른지 확인하세요."
            )
        elif "400" in error_text:
            st.error(
                "요청 형식 오류가 발생했습니다. Function Calling 스키마와 "
                "필수 인자를 확인하세요."
            )
            st.code(error_text)
        elif "429" in error_text:
            st.error(
                "API 요청 한도 또는 크레딧 문제가 발생했습니다."
            )
        else:
            st.error(f"오류가 발생했습니다: {error}")
