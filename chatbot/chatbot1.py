import json
import os
import re
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

# =========================================================
# 1. 기본 설정
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
JSON_PATH = BASE_DIR / "team4_output.json"
TXT_PATH = BASE_DIR / "team4_output.txt"
MODEL = "gpt-5-mini"

load_dotenv()

st.set_page_config(
    page_title="취약점 찾아조 AI 챗봇",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# 2. JSON -> TXT 변환 및 로드
# =========================================================
def convert_json_to_text(json_path: Path, txt_path: Path) -> None:
    """팀4 JSON 결과를 사람이 읽기 쉬운 텍스트 보고서로 변환한다."""
    if not json_path.exists():
        raise FileNotFoundError(f"JSON 파일을 찾을 수 없습니다: {json_path}")

    with json_path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("team4_output.json의 최상위 구조는 리스트여야 합니다.")

    lines: list[str] = []
    for item in records:
        lines.extend(
            [
                f"[취약점 {item.get('priority_rank', '-')}순위]",
                f"CVE ID: {item.get('cve_id', 'UNKNOWN')}",
                f"CWE: {item.get('cwe', 'UNKNOWN')}",
                f"CVSS 점수: {item.get('cvss_score', 0)}",
                f"실제 등급: {item.get('severity', 'UNKNOWN')}",
                f"예측 등급: {item.get('predicted_severity', 'UNKNOWN')}",
                f"우선순위 점수: {item.get('priority_score', 0)}",
                f"대응 우선순위: {item.get('response_priority', 'UNKNOWN')}",
                f"공격 경로: {item.get('attack_vector', 'UNKNOWN')}",
                f"공격 복잡도: {item.get('attack_complexity', 'UNKNOWN')}",
                f"필요 권한: {item.get('privileges_required', 'UNKNOWN')}",
                f"사용자 상호작용: {item.get('user_interaction', 'UNKNOWN')}",
                f"설명: {item.get('description', '')}",
                "-" * 80,
            ]
        )

    txt_path.write_text("\n".join(lines), encoding="utf-8")


@st.cache_data(show_spinner=False)
def load_report_text() -> str:
    """텍스트 보고서를 불러오며, 없으면 JSON에서 자동 생성한다."""
    if not TXT_PATH.exists():
        convert_json_to_text(JSON_PATH, TXT_PATH)
    return TXT_PATH.read_text(encoding="utf-8")


@st.cache_data(show_spinner=False)
def load_json_records() -> list[dict[str, Any]]:
    """정확한 계산에 사용할 구조화된 JSON 데이터를 불러온다."""
    if not JSON_PATH.exists():
        return []
    with JSON_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)
    return data if isinstance(data, list) else []


REPORT_TEXT = load_report_text()
VULNERABILITY_RECORDS = load_json_records()


# =========================================================
# 3. 로컬 텍스트 보고서 검색
# =========================================================
def extract_search_terms(question: str) -> list[str]:
    """질문에서 CVE, 제품명, 버전처럼 검색에 유용한 단어를 추출한다."""
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", question, flags=re.IGNORECASE)
    words = re.findall(r"[A-Za-z][A-Za-z0-9._-]{2,}", question)

    stopwords = {
        "what", "this", "that", "with", "from", "about", "risk", "score",
        "vulnerability", "cve", "the", "and", "for", "find", "search",
    }

    terms: list[str] = []
    for term in cves + words:
        normalized = term.upper() if term.lower().startswith("cve-") else term
        if normalized.lower() not in stopwords and normalized not in terms:
            terms.append(normalized)
    return terms[:8]


def search_report_text(question: str, max_blocks: int = 5) -> str:
    """전체 TXT를 매번 모델에 보내지 않고 관련 취약점 블록만 찾아 반환한다."""
    terms = extract_search_terms(question)
    if not terms:
        return ""

    blocks = REPORT_TEXT.split("-" * 80)
    scored: list[tuple[int, str]] = []

    for block in blocks:
        lower_block = block.lower()
        score = sum(3 if term.lower().startswith("cve-") else 1 for term in terms if term.lower() in lower_block)
        if score > 0:
            scored.append((score, block.strip()))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected = [block for _, block in scored[:max_blocks] if block]
    return "\n\n".join(selected)


# =========================================================
# 4. Function Calling 함수
# =========================================================
def calculate_risk(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    cvss_score: float = 0.0,
) -> dict[str, Any]:
    """CVSS 요소를 바탕으로 프로젝트용 위험도 점수를 재계산한다."""
    vector_weight = {
        "NETWORK": 30,
        "ADJACENT": 22,
        "LOCAL": 14,
        "PHYSICAL": 6,
    }
    complexity_weight = {"LOW": 20, "HIGH": 8}
    privilege_weight = {"NONE": 25, "LOW": 15, "HIGH": 5}
    interaction_weight = {"NONE": 15, "REQUIRED": 5}

    av = attack_vector.upper()
    ac = attack_complexity.upper()
    pr = privileges_required.upper()
    ui = user_interaction.upper()

    metric_score = (
        vector_weight.get(av, 10)
        + complexity_weight.get(ac, 8)
        + privilege_weight.get(pr, 8)
        + interaction_weight.get(ui, 5)
    )

    cvss_component = max(0.0, min(float(cvss_score), 10.0)) * 1.0
    final_score = round(min(metric_score + cvss_component, 100), 1)

    if final_score >= 85:
        priority = "긴급 대응"
        level = "CRITICAL"
    elif final_score >= 70:
        priority = "24시간 이내 조치"
        level = "HIGH"
    elif final_score >= 45:
        priority = "단기 조치"
        level = "MEDIUM"
    else:
        priority = "정기 점검"
        level = "LOW"

    reasons = []
    if av == "NETWORK":
        reasons.append("네트워크를 통한 원격 공격 가능")
    if ac == "LOW":
        reasons.append("공격 복잡도가 낮음")
    if pr == "NONE":
        reasons.append("사전 권한이 필요하지 않음")
    if ui == "NONE":
        reasons.append("사용자 동작 없이 악용 가능")

    return {
        "risk_score": final_score,
        "risk_level": level,
        "response_priority": priority,
        "reason": reasons,
        "input_metrics": {
            "attack_vector": av,
            "attack_complexity": ac,
            "privileges_required": pr,
            "user_interaction": ui,
            "cvss_score": cvss_score,
        },
    }


def rank_vulnerabilities(cve_ids: list[str]) -> dict[str, Any]:
    """JSON 결과에서 요청된 CVE들을 찾아 프로젝트 우선순위 기준으로 재정렬한다."""
    requested = {cve.upper() for cve in cve_ids}
    matched = [
        record for record in VULNERABILITY_RECORDS
        if str(record.get("cve_id", "")).upper() in requested
    ]

    matched.sort(
        key=lambda x: (
            float(x.get("priority_score", 0)),
            float(x.get("cvss_score", 0)),
            x.get("attack_vector") == "NETWORK",
            x.get("privileges_required") == "NONE",
            x.get("user_interaction") == "NONE",
        ),
        reverse=True,
    )

    ranked = []
    for rank, item in enumerate(matched, start=1):
        ranked.append(
            {
                "rank": rank,
                "cve_id": item.get("cve_id"),
                "priority_score": item.get("priority_score"),
                "cvss_score": item.get("cvss_score"),
                "severity": item.get("predicted_severity") or item.get("severity"),
                "response_priority": item.get("response_priority"),
                "attack_vector": item.get("attack_vector"),
                "privileges_required": item.get("privileges_required"),
                "user_interaction": item.get("user_interaction"),
                "description": item.get("description"),
            }
        )

    missing = sorted(requested - {str(x.get("cve_id", "")).upper() for x in matched})
    return {"ranked_vulnerabilities": ranked, "not_found": missing}


FUNCTION_MAP = {
    "calculate_risk": calculate_risk,
    "rank_vulnerabilities": rank_vulnerabilities,
}

TOOLS = [
    {"type": "web_search"},
    {
        "type": "function",
        "name": "calculate_risk",
        "description": "공격 경로, 복잡도, 필요 권한, 사용자 상호작용, CVSS를 바탕으로 위험도와 대응 우선순위를 계산한다.",
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
                "cvss_score": {"type": "number"},
            },
            "required": [
                "attack_vector",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
            ],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "rank_vulnerabilities",
        "description": "세션 또는 팀4 결과에 포함된 여러 CVE의 조치 우선순위를 다시 계산하고 정렬한다.",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                }
            },
            "required": ["cve_ids"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]

SYSTEM_PROMPT = """
너는 '취약점 찾아조' 프로젝트의 보안 분석 챗봇이다.

반드시 다음 원칙을 지켜라.
1. 최신 제품 취약점, 특정 CVE 사실 확인, 패치 버전 조회는 web_search를 사용한다.
2. 여러 취약점의 순위 비교나 CVSS 요소 기반 위험도 재계산은 function tool을 사용한다.
3. 이미 대화에서 나온 결과를 설명하거나 요약할 때는 새 도구를 호출하지 말고 세션 내용과 제공된 로컬 보고서 문맥을 사용한다.
4. 복합 질문은 web_search로 취약점을 확인한 뒤 calculate_risk 또는 rank_vulnerabilities를 사용한다.
5. 확인되지 않은 CVE나 제품 정보를 만들어내지 않는다.
6. 답변은 한국어로 작성하고, 핵심 결과 → 근거 → 권고 조치 순서로 간결하게 설명한다.
7. 위험도 계산 결과는 프로젝트 내부 우선순위 점수이며 공식 CVSS 재산정값과 다를 수 있음을 필요한 경우 밝힌다.
8. 로컬 보고서에 같은 점수의 취약점이 여러 개 있으면 실제 노출 여부, 자산 중요도, 악용 가능성, 패치 가능 여부가 추가 우선순위 기준임을 설명한다.
"""


# =========================================================
# 5. OpenAI Responses API 실행
# =========================================================
def run_chatbot(user_question: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(".env 파일에 OPENAI_API_KEY를 설정해 주세요.")

    client = OpenAI(api_key=api_key)
    local_context = search_report_text(user_question)

    current_input: list[dict[str, Any]] = []

    # 직전 대화 일부만 전달하여 세션 설명 질문을 처리한다.
    for message in st.session_state.messages[-10:]:
        current_input.append(
            {
                "role": message["role"],
                "content": message["content"],
            }
        )

    context_message = (
        "아래는 팀4 JSON을 TXT로 변환한 로컬 취약점 보고서에서 "
        "현재 질문과 관련된 부분이다. 관련 내용이 없으면 비어 있을 수 있다.\n\n"
        f"{local_context or '[관련 로컬 결과 없음]'}"
    )
    current_input.append({"role": "developer", "content": context_message})
    current_input.append({"role": "user", "content": user_question})

    response = client.responses.create(
        model=MODEL,
        instructions=SYSTEM_PROMPT,
        input=current_input,
        tools=TOOLS,
        tool_choice="auto",
    )

    # 사용자 정의 함수 호출이 있으면 실행 후 모델에 결과를 다시 전달한다.
    for _ in range(5):
        function_calls = [item for item in response.output if item.type == "function_call"]
        if not function_calls:
            return response.output_text

        tool_outputs = []
        for call in function_calls:
            function = FUNCTION_MAP.get(call.name)
            if function is None:
                result = {"error": f"지원하지 않는 함수: {call.name}"}
            else:
                try:
                    arguments = json.loads(call.arguments)
                    result = function(**arguments)
                except Exception as error:
                    result = {"error": str(error)}

            tool_outputs.append(
                {
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": json.dumps(result, ensure_ascii=False),
                }
            )

        response = client.responses.create(
            model=MODEL,
            instructions=SYSTEM_PROMPT,
            previous_response_id=response.id,
            input=tool_outputs,
            tools=TOOLS,
            tool_choice="auto",
        )

    return "함수 호출이 반복되어 처리를 중단했습니다. 질문을 조금 더 구체적으로 입력해 주세요."


# =========================================================
# 6. Streamlit UI
# =========================================================
st.title("🛡️ 취약점 찾아조 AI 챗봇")
st.caption("Web Search + Function Calling + 팀4 위험도 결과 TXT 연동")

with st.sidebar:
    st.header("ℹ️ Information")
    st.write("팀3 담당: 머신러닝 위험도 결과 연동 및 보안 질의응답")
    st.write(f"로드된 취약점: **{len(VULNERABILITY_RECORDS):,}개**")
    st.write(f"로컬 보고서: `{TXT_PATH.name}`")

    st.divider()
    st.subheader("질문 예시")
    st.code("Apache 2.4.49 취약점 있어?")
    st.code("CVE-2026-57752가 뭐야?")
    st.code("이 3개 취약점 중 뭐부터 조치해야 해?")
    st.code("공격 경로 NETWORK, 권한 필요없으면 위험도 어때?")
    st.code("방금 나온 결과 요약해줘")
    st.code("MySQL 5.7 취약점 찾아서 위험도까지 알려줘")

    if st.button("대화 초기화", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

question = st.chat_input("취약점, 위험도, 조치 우선순위를 질문하세요.")

if question:
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        with st.spinner("취약점 분석 중..."):
            try:
                answer = run_chatbot(question)
            except Exception as error:
                answer = f"오류가 발생했습니다: `{error}`"
        st.markdown(answer)

    st.session_state.messages.append({"role": "assistant", "content": answer})