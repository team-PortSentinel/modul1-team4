import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import os
from openai import OpenAI
from dotenv import load_dotenv
import mkpdf # PDF 엔진 임포트

# 스크립트 실행 시 가장 먼저 .env 파일을 읽어오도록 설정합니다.
load_dotenv()

def fetch_ai_mitigation(cve_data, api_key=None):
    """실제 OpenAI API 연동 및 시뮬레이션 결과 반환"""
    # 환경변수 또는 파라미터로 받은 API 키 확인
    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")
        
    if not api_key:
        return "⚠️ OpenAI API 키가 설정되지 않았습니다. .env 파일을 확인해주세요."

    try:
        client = OpenAI(api_key=api_key)
        
        # 기획서 상세 조건을 반영한 프롬프트 설정 (제로 트러스트, 방화벽 가이드 필수 포함)
        response = client.chat.completions.create(
            model="gpt-5.5", 
            messages=[
                {
                    "role": "system",
                    "content": (
                        "당신은 최고 수준의 모의침투 테스트 전문가이자 보안 아키텍트입니다. "
                        "분석된 위협과 취약점 데이터를 바탕으로 구체적인 대응 방안을 작성해야 합니다. "
                        "**응답에는 반드시 다음 두 가지 항목이 명시적으로 포함되어야 합니다:**\n"
                        "1) 제로 트러스트(Zero Trust) 관점의 조건부 접속 차단 정책\n"
                        "2) 시스템 방어를 위한 구체적인 방화벽(Firewall) 설정 가이드(차단/허용 규칙 등)"
                    )
                },
                {
                    "role": "user", 
                    "content": f"다음 스캔된 대상의 취약점 데이터를 분석하고, 지시된 조건에 맞추어 조치 방안을 제시해주세요:\n\n{cve_data}"
                }
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI 분석 중 오류가 발생했습니다: {str(e)}"

# ==========================================
# 0. 페이지 기본 설정 및 커스텀 CSS
# ==========================================
st.set_page_config(page_title="AI 기반 침투 테스트 지원 시스템", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded") 
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 800; color: #1f77b4; margin-bottom: 5px; } 
    .sub-title { font-size: 1rem; color: #555; margin-bottom: 30px; } 
    .badge-kev { background:#fcebeb; color:#d62728; padding:3px 10px; border-radius:20px; font-size:14px; font-weight:bold; margin-left:10px; vertical-align: middle;} 
    .fix-box { background:#f4f9f1; border: 1px solid #c3e6cb; border-radius:8px; padding:20px; margin-top:15px; color:#285b1c; font-size:15px; line-height:1.6; } 
    .top-metric-card { border: 1px solid #e6e6e6; border-radius: 8px; padding: 20px 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background-color: white; }
    .top-metric-label { font-size: 1rem; color: #555; margin-bottom: 10px; font-weight: 600;}
    .top-metric-val-blue { font-size: 1.8rem; font-weight: bold; color: #1f77b4; }
    .top-metric-val-red { font-size: 1.8rem; font-weight: bold; color: #d62728; }
    
    /* Streamlit 요소들의 기본 마진 조정 */
    div[data-testid="stMetric"] { text-align: center; }
</style>
""", unsafe_allow_html=True)

# 데이터 셋
SAMPLE_RESULT = [ 
    {"cve_id": "CVE-2021-41773", "service": "Apache httpd 2.4.49", "cvss": 7.5, "kev": True, "predicted_risk": 0.89, "attack_vector": "NETWORK", "complexity": "LOW", "privileges": "NONE", "user_int": "NONE", "description": "경로 탐색 → 원격 코드 실행. 실제 공격에 활발히 쓰이는 취약점."}, 
    {"cve_id": "CVE-2021-42013", "service": "Apache httpd 2.4.49", "cvss": 9.8, "kev": True, "predicted_risk": 0.82, "attack_vector": "NETWORK", "complexity": "LOW", "privileges": "NONE", "user_int": "NONE", "description": "41773 패치 우회. 경로 탐색으로 임의 파일 노출 및 RCE 가능."}, 
    {"cve_id": "CVE-2016-6210", "service": "OpenSSH 7.4", "cvss": 5.9, "kev": False, "predicted_risk": 0.54, "attack_vector": "NETWORK", "complexity": "LOW", "privileges": "LOW", "user_int": "NONE", "description": "사용자 존재 여부를 응답 시간 차이로 추측 가능(정보 노출)."} 
]

# 세션 상태 초기화
if "messages" not in st.session_state: 
    st.session_state.messages = [{"role": "assistant", "content": "안녕하세요! Nmap 스캔 결과를 하단에 붙여넣으면 분석을 시작합니다."}] 
if "is_analyzed" not in st.session_state: 
    st.session_state.is_analyzed = False 
if "ai_response_cache" not in st.session_state: 
    st.session_state.ai_response_cache = None 

# 사이드바 구성
with st.sidebar: 
    st.markdown("### 🛡️ 챗봇 영역") 
    with st.container(height=350): 
        for msg in st.session_state.messages: 
            with st.chat_message(msg["role"]): 
                st.markdown(msg["content"])
                
    # 프롬프트 입력창
    if prompt := st.chat_input("Nmap 스캔 결과를 여기에 붙여넣으세요..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        st.session_state.is_analyzed = True
        st.rerun()

# 메인 화면
st.markdown("<div class='main-title'>AI 기반 침투 테스트 지원 대시보드</div>", unsafe_allow_html=True) 
st.markdown("<div class='sub-title'>자동화된 Nmap 분석, 최신 CVE 검색 및 머신러닝(Random Forest) 기반 위험도 예측</div>", unsafe_allow_html=True) 

if not st.session_state.is_analyzed: 
    st.info("👈 좌측 챗봇에 Nmap 스캔 결과를 입력하여 분석을 시작해주세요.") 
else:
    # 데이터 처리
    df = pd.DataFrame(SAMPLE_RESULT)
    def categorize_risk(score):
        if score >= 0.8: return "High"
        elif score >= 0.5: return "Medium"
        else: return "Low"
    df['Risk_Category'] = df['predicted_risk'].apply(categorize_risk)
    
    # 공통 색상 맵
    color_discrete_map = {'High': '#d62728', 'Medium': '#ffb01e', 'Low': '#2ca02c'}

    # ----------------------------------------------------
    # 1. 상단: 대시보드 요약 (Metrics)
    # ----------------------------------------------------
    st.markdown("### 상단: 대시보드 요약")
    st.markdown("<hr style='margin: 0px 0px 20px 0px; border-top: 2px solid #333;'>", unsafe_allow_html=True)
    
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    
    # 커스텀 메트릭 카드 렌더링 함수
    def render_metric(label, value, is_red=False):
        val_class = "top-metric-val-red" if is_red else "top-metric-val-blue"
        return f"""<div class='top-metric-card'>
                    <div class='top-metric-label'>{label}</div>
                    <div class='{val_class}'>{value}</div>
                   </div>"""

    m_col1.markdown(render_metric("스캔 대상", "1"), unsafe_allow_html=True)
    m_col2.markdown(render_metric("열린 포트", "5"), unsafe_allow_html=True)
    m_col3.markdown(render_metric("식별된 서비스", "4"), unsafe_allow_html=True)
    m_col4.markdown(render_metric("취약점 수", str(len(df)), is_red=True), unsafe_allow_html=True)
    
    max_risk_val = "High" if df['predicted_risk'].max() >= 0.8 else "Medium"
    m_col5.markdown(render_metric("위험도(최대)", max_risk_val, is_red=True), unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # 2. 중단: 3분할 차트 및 목록
    # ----------------------------------------------------
    c_col1, c_col2, c_col3 = st.columns([1.2, 1.2, 1])
    
    # A. 위험도 통계 분포 (Pie Chart)
    with c_col1:
        st.markdown("**위험도 통계 분포**")
        risk_counts = df['Risk_Category'].value_counts().reset_index()
        risk_counts.columns = ['Risk_Category', 'Count']
        
        fig_pie = px.pie(risk_counts, values='Count', names='Risk_Category', 
                         color='Risk_Category', color_discrete_map=color_discrete_map, hole=0.45)
        fig_pie.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300)
        st.plotly_chart(fig_pie, use_container_width=True)
        
        # PDF용 이미지 저장
        try: fig_pie.write_image("pie_chart.png")
        except: pass

    # B. ML 예측 위험도 순위 (Horizontal Bar Chart)
    with c_col2:
        st.markdown("**ML 예측 위험도 순위 (Random Forest)**")
        df_sorted = df.sort_values(by='predicted_risk', ascending=True)
        
        fig_bar = px.bar(df_sorted, x='predicted_risk', y='cve_id', orientation='h', 
                         text='predicted_risk', color='Risk_Category', color_discrete_map=color_discrete_map)
        fig_bar.update_traces(textposition='outside')
        fig_bar.update_layout(xaxis_title='', yaxis_title='', showlegend=False, margin=dict(l=0, r=0, t=10, b=0), height=300)
        st.plotly_chart(fig_bar, use_container_width=True)
        
        # PDF용 이미지 저장
        try: fig_bar.write_image("bar_chart.png")
        except: pass

    # C. 주요 서비스 목록 (Table)
    with c_col3:
        st.markdown("**주요 서비스 목록**")
        service_data = pd.DataFrame({
            "서비스": ["Apache", "OpenSSH", "MySQL"],
            "포트": ["80/443", "22", "3306"]
        })
        # Streamlit dataframe 사용 (인덱스 숨김)
        st.dataframe(service_data, use_container_width=True, hide_index=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # 3. 하단: AI 발견 취약점 상세 리포트
    # ----------------------------------------------------
    st.markdown("### 하단: AI 발견 취약점 상세 리포트 (제로 트러스트 적용)")
    st.markdown("<hr style='margin: 0px 0px 20px 0px; border-top: 2px solid #333;'>", unsafe_allow_html=True)
    
    # 가장 위험도가 높은 취약점을 1위로 선정
    top_cve = df.loc[df['predicted_risk'].idxmax()]
    kev_badge = "<span class='badge-kev'>KEV 악용중</span>" if top_cve['kev'] else ""
    
    st.markdown(f"### 🥇 [우선순위 1위] {top_cve['cve_id']} {kev_badge} <span style='color:#555; font-size:1.5rem;'>({top_cve['service']})</span>", unsafe_allow_html=True)
    
    # NVD 설명
    st.info(f"ℹ️ **NVD 취약점 설명:** {top_cve['description']}")
    st.markdown("<br>", unsafe_allow_html=True)
    
    # ML 기반 위험도 예측 결과
    st.markdown("##### 🤖 ML 기반 위험도 예측 결과 (Random Forest Regressor)")
    r_col1, r_col2, r_col3, r_col4, r_col5 = st.columns(5)
    
    r_col1.metric("Attack Vector", top_cve['attack_vector'])
    r_col2.metric("Complexity", top_cve['complexity'])
    r_col3.metric("Privileges", top_cve['privileges'])
    r_col4.metric("User Interaction", top_cve['user_int'])
    
    # 예측 Severity 커스텀 붉은색 박스
    severity_html = f"""
    <div style='border: 1.5px solid #ffcccc; border-radius: 8px; padding: 15px; text-align: center; background-color: #fffcfc;'>
        <div style='font-size: 0.9rem; color: #d62728; margin-bottom: 5px;'>예측 Severity (Risk)</div>
        <div style='font-size: 2.2rem; font-weight: bold; color: #d62728; line-height: 1;'>{top_cve['predicted_risk']}</div>
    </div>
    """
    r_col5.markdown(severity_html, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # AI 제로 트러스트 대응 방안
    st.markdown("##### 🛡️ AI 제로 트러스트 대응 방안")
    
    if st.session_state.get("ai_response_cache") is None:
        with st.spinner("최신 위협 인텔리전스와 제로 트러스트 관점을 바탕으로 대응 방안을 생성하고 있습니다..."):
            cve_summary_str = df[['cve_id', 'service', 'cvss', 'predicted_risk', 'description']].to_string(index=False)
            ai_result = fetch_ai_mitigation(cve_summary_str)
            st.session_state.ai_response_cache = ai_result
            
    st.markdown(f"<div class='fix-box'>{st.session_state.get('ai_response_cache')}</div>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # 하단 버튼 영역 (PDF 다운로드 등)
    # ----------------------------------------------------
    st.markdown("<br><br>", unsafe_allow_html=True)
    btn_col1, btn_col2, btn_col3 = st.columns([3, 4, 3])
    
    with btn_col2: # 중앙 정렬
        if st.button("📄 PDF 보고서 생성 및 다운로드", use_container_width=True):
            with st.spinner("PDF 보고서를 생성하는 중입니다..."):
                ai_text = st.session_state.get('ai_response_cache', "생성된 AI 대응방안이 없습니다.")
                
                # mkpdf.py 연동
                is_success = mkpdf.create_pdf_report(
                    file_path="report.pdf", 
                    vulns=SAMPLE_RESULT, 
                    top_cve=top_cve['cve_id'], 
                    ai_text=ai_text, 
                    pie_path="pie_chart.png", 
                    bar_path="bar_chart.png"
                )
                
                if is_success and os.path.exists("report.pdf"):
                    with open("report.pdf", "rb") as f:
                        st.download_button(
                            label="📥 완료! 여기를 눌러 PDF 다운로드",
                            data=f,
                            file_name="AI_Penetration_Test_Report.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                else:
                    st.error("PDF 생성 중 오류가 발생했습니다. mkpdf.py 모듈 상태를 확인해주세요.")