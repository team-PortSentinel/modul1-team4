"""
취약점 분석 시스템 (풀 다크 · 2단 레이아웃 + PDF 보고서 + JSON/Live Scanner 동적 연단 파이프라인)
"""

import re
import os
import sys
import html
import json
from io import BytesIO
from datetime import datetime
from collections import Counter

import streamlit as st
import plotly.graph_objects as go

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

# scanner.py 모듈로부터 실시간 라이브 스캔 함수 연동
from utils.scanner import run_scanner

# 팀2(취약점 분석) 모듈 연동 
# team2 폴더 안의 app_bridge를 통해 팀2 분석 기능을 하나의 함수로 사용
from team2.app_bridge import run_vulnerability_scan

# 팀2 변수 지정 (일단 team2_result로 해놨고, team1_result만 받아서 사용하면 됨)
# team2_result = run_vulnerability_scan(team1_result) 


# 입력 처리 및 Nmap 대기 제어 
def run_analysis(user_text):
    # 만약 scanner.py에서 에러 피드백 딕셔너리 구조가 넘어왔을 경우 UI 크래시 방지 처리
    if isinstance(user_text, dict) and not user_text.get("success", True):
        error_msg = user_text.get("error", "알 수 없는 스캔 예외")
        st.session_state.messages.append({"role": "assistant", "text": f"❌ 스캔 작업이 실패했습니다: {error_msg}"})
        st.error(f"스캔 도중 치명적인 에러가 발생했습니다: {error_msg}")
        return

    st.session_state.messages.append({"role": "user", "text": "스캔 데이터 업로드 및 실시간 모델 추론 시작."})

    # 실시간 JSON/Text 통합 파서로 변환 처리 수행
    st.session_state.cves = analyze_scan(user_text)
    cves = st.session_state.cves
    top = max(cves, key=lambda c: c["predicted_risk"])
    st.session_state.messages.append({"role": "assistant", "text":
                                      f"분석 완료 — 취약점 {len(cves)}건 탐지. 최고위험 {top['cve_id']} "
                                      f"({severity(top['predicted_risk'])[0]}). 우측/팝업에서 상세 확인."})
    st.session_state.pending_dialog = True


# 1) Live Nmap 실시간 스캔 가동 처리 (scanner.py 결과 활용)
if start_live_scan:
    with st.spinner(f"🔍 '{target_input}'을(를) 대상으로 Nmap 실시간 정밀 스캔 가동 중..."):
        raw_output = run_scanner(target_input, scan_options)
    run_analysis(raw_output)
    st.rerun()
