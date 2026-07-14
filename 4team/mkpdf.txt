from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
import os
import re

def register_fonts():
    """맑은 고딕 일반 폰트와 굵은 폰트를 등록하여 한글을 지원하게 합니다."""
    try:
        pdfmetrics.registerFont(TTFont('MalgunGothic', 'malgun.ttf'))
        # 굵은 글씨체 폰트(malgunbd.ttf) 등록
        if os.path.exists('malgunbd.ttf'):
            pdfmetrics.registerFont(TTFont('MalgunGothic-Bold', 'malgunbd.ttf'))
            addMapping('MalgunGothic', 0, 0, 'MalgunGothic') # 일반
            addMapping('MalgunGothic', 1, 0, 'MalgunGothic-Bold') # 굵게(Bold)
    except Exception as e:
        print(f"폰트 로드 에러 (PDF에 기본 폰트가 적용되며 한글이 깨질 수 있습니다): {e}")

def clean_html_for_pdf(text):
    """스트림릿에서 쓰는 태그나 마크다운을 ReportLab이 이해하는 태그로 변환"""
    if not text:
        return ""
    text = text.replace('\n', '<br/>')
    text = re.sub(r'<br\s*>', '<br/>', text)
    # 마크다운 **텍스트** 를 <b>텍스트</b> 로 변환
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    return text

def create_pdf_report(file_path, vulns, top_cve, ai_text, pie_path, bar_path):
    """대시보드의 구성과 동일하게 표, 메트릭, 차트가 모두 포함된 PDF 생성"""
    register_fonts()
    
    # PDF 문서 설정 (A4 사이즈, 마진 설정)
    doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    # --- 스타일 정의 (에러 방지를 위해 fontName은 MalgunGothic으로 고정) ---
    title_style = ParagraphStyle(name='Title', fontName='MalgunGothic', fontSize=18, spaceAfter=20, alignment=TA_CENTER)
    heading_style = ParagraphStyle(name='Heading', fontName='MalgunGothic', fontSize=13, spaceAfter=10, spaceBefore=15)
    normal_style = ParagraphStyle(name='Normal', fontName='MalgunGothic', fontSize=10, leading=15)
    center_style = ParagraphStyle(name='Center', fontName='MalgunGothic', fontSize=10, leading=15, alignment=TA_CENTER)
    
    # 1. 타이틀
    story.append(Paragraph("<b>AI 기반 침투 테스트 분석 및 대응 보고서</b>", title_style))
    story.append(Spacer(1, 10))
    
    # ----------------------------------------------------
    # 2. 상단: 대시보드 요약 (Metrics Table)
    # ----------------------------------------------------
    story.append(Paragraph("<b>1. 대시보드 요약</b>", heading_style))
    
    max_score = max([v.get('predicted_risk', 0) for v in vulns]) if vulns else 0
    max_risk_label = 'High' if max_score >= 0.8 else ('Medium' if max_score >= 0.5 else 'Low')
    max_risk_color = 'red' if max_risk_label == 'High' else ('orange' if max_risk_label == 'Medium' else 'green')
    unique_services = len(set([v.get('service', 'Unknown') for v in vulns]))
    
    summary_data = [
        [Paragraph("<b>스캔 대상</b>", center_style), Paragraph("<b>열린 포트</b>", center_style), 
         Paragraph("<b>식별된 서비스</b>", center_style), Paragraph("<b>취약점 수</b>", center_style), 
         Paragraph("<b>위험도(최대)</b>", center_style)],
        [Paragraph("1", center_style), Paragraph("5", center_style), 
         Paragraph(str(unique_services), center_style), Paragraph(str(len(vulns)), center_style), 
         Paragraph(f"<font color='{max_risk_color}'><b>{max_risk_label}</b></font>", center_style)]
    ]
    
    t_summary = Table(summary_data, colWidths=[103, 103, 103, 103, 103])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ('BOX', (0, 0), (-1, -1), 1, colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))

    # ----------------------------------------------------
    # 3. 중단: 시각화 차트
    # ----------------------------------------------------
    story.append(Paragraph("<b>2. 스캔 및 위험도 분석 시각화</b>", heading_style))
    chart_row = []
    
    # 이미지가 존재할 경우 병렬 배치(Table 사용)
    if pie_path and os.path.exists(pie_path):
        chart_row.append(RLImage(pie_path, width=250, height=200))
    if bar_path and os.path.exists(bar_path):
        chart_row.append(RLImage(bar_path, width=250, height=200))
        
    if chart_row:
        t_charts = Table([chart_row], colWidths=[255, 255])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(t_charts)
    else:
        story.append(Paragraph("차트 이미지를 찾을 수 없습니다.", normal_style))
    story.append(Spacer(1, 15))

    # ----------------------------------------------------
    # 4. 하단: 우선순위 취약점 상세 정보 (ML 예측 결과 포함)
    # ----------------------------------------------------
    story.append(Paragraph("<b>3. AI 발견 취약점 상세 리포트</b>", heading_style))
    
    # 제일 위험한 CVE 찾기
    top_vuln = next((v for v in vulns if v.get('cve_id') == top_cve), vulns[0] if vulns else None)
    
    if top_vuln:
        kev_badge = " <font color='red'>(KEV 악용중)</font>" if top_vuln.get('kev') else ""
        story.append(Paragraph(f"<b>[ 우선순위 1위 ] {top_vuln.get('cve_id')}</b>{kev_badge}", normal_style))
        story.append(Paragraph(f"<b>서비스:</b> {top_vuln.get('service')}", normal_style))
        story.append(Spacer(1, 5))
        
        # NVD 설명 박스 느낌
        desc_data = [[Paragraph(f"<b>NVD 취약점 설명:</b> {top_vuln.get('description')}", normal_style)]]
        t_desc = Table(desc_data, colWidths=[515])
        t_desc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.aliceblue),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.lightblue),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_desc)
        story.append(Spacer(1, 10))
        
        # ML 피처 값 표 (대시보드 하단의 5분할 메트릭스 구현)
        story.append(Paragraph("<b>[ ML 기반 위험도 예측 결과 ]</b>", normal_style))
        story.append(Spacer(1, 5))
        
        ml_data = [
            [Paragraph("<b>Attack Vector</b>", center_style), Paragraph("<b>Complexity</b>", center_style), 
             Paragraph("<b>Privileges</b>", center_style), Paragraph("<b>User Int.</b>", center_style), 
             Paragraph("<b><font color='#d62728'>예측 Severity</font></b>", center_style)],
            [Paragraph(top_vuln.get('attack_vector', ''), center_style),
             Paragraph(top_vuln.get('complexity', ''), center_style),
             Paragraph(top_vuln.get('privileges', ''), center_style),
             Paragraph(top_vuln.get('user_int', ''), center_style),
             Paragraph(f"<font color='#d62728' size='14'><b>{top_vuln.get('predicted_risk', '')}</b></font>", center_style)]
        ]
        t_ml = Table(ml_data, colWidths=[103, 103, 103, 103, 103])
        t_ml.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('BACKGROUND', (4, 0), (4, 1), colors.snow), # Severity 영역 배경색
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('BOX', (0, 0), (-1, -1), 1, colors.grey),
            ('BOX', (4, 0), (4, 1), 1.5, colors.red), # Severity 강조 붉은 박스
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_ml)
        story.append(Spacer(1, 15))

    # ----------------------------------------------------
    # 5. AI 대응 방안
    # ----------------------------------------------------
    story.append(Paragraph("<b>4. AI 제로 트러스트 대응 방안</b>", heading_style))
    formatted_ai_text = clean_html_for_pdf(ai_text)
    
    ai_box_data = [[Paragraph(formatted_ai_text, normal_style)]]
    t_ai = Table(ai_box_data, colWidths=[515])
    t_ai.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f4f9f1')), # 대시보드의 녹색 배경 적용
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#c3e6cb')),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(t_ai)
        
    # PDF 빌드
    try:
        doc.build(story)
        return True
    except Exception as e:
        print(f"PDF 생성 중 오류 발생: {e}")
        return False