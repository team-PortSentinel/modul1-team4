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



# 1) Live Nmap 실시간 스캔 가동 처리 (scanner.py 결과 활용)
# target_input : ip 혹은 도메인 입력값
# scan_options : 검색 옵션 입력값
if start_live_scan:
    with st.spinner(f"🔍 '{target_input}'을(를) 대상으로 Nmap 실시간 정밀 스캔 가동 중..."):
        raw_output = run_scanner(target_input, scan_options)
    st.rerun()
