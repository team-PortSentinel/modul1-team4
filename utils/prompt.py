# ==========================================================
# prompt_builder.py
# 역할 :
# Parser가 정리한 Nmap 결과를
# OpenAI가 이해하기 쉬운 Prompt 형태로 변환한다.
# ==========================================================


class PromptBuilder:

    # ------------------------------------------------------
    # 생성자
    # parser에서 전달받은 Dictionary 데이터를 저장한다.
    # ------------------------------------------------------
    def __init__(self, parsed_data):
        self.parsed_data = parsed_data

    # ------------------------------------------------------
    # AI에게 전달할 Prompt 생성
    # ------------------------------------------------------
    def build_prompt(self):

        # 기본 Prompt
        prompt = """
당신은 10년 이상의 경력을 가진 침투테스트 전문가이자 보안 컨설턴트입니다.

아래 Nmap 스캔 결과를 분석하여 최신 정보를 기반으로 취약점을 분석하세요.

Web Search를 반드시 활용하여 최신 CVE 정보를 참고하세요.

다음 형식으로 답변하세요.

==============================

1. 시스템 정보

2. 서비스별 취약점

3. 관련 CVE

4. CVSS 점수

5. 위험도
(High / Medium / Low)

6. 공격 가능성

7. 공개된 Exploit 존재 여부

8. 대응 방안

9. 참고한 공식 출처

==============================

"""

        # --------------------------------------------------
        # Host 정보 추가
        # --------------------------------------------------

        for host in self.parsed_data["hosts"]:

            prompt += f"\nHost IP : {host['ip']}\n"
            prompt += f"Hostname : {host['hostname']}\n"
            prompt += f"Status : {host['status']}\n"
            prompt += f"OS : {host['os']['name']}\n"

            prompt += "\n========== Open Ports ==========\n"

            # ----------------------------------------------
            # 열린 포트 정보 추가
            # ----------------------------------------------

            for port in host["ports"]:

                prompt += (
                    f"""
Port : {port['port']}/{port['protocol']}

State : {port['state']}

Service : {port['service']}

Product : {port['product']}

Version : {port['version']}

Extra Info : {port['extrainfo']}

----------------------------------------
"""
                )

        # 마지막 요청사항

        prompt += """

위 서비스들의

- 취약점

- CVE 번호

- CVSS 점수

- 위험도

- 공개 Exploit 존재 여부

- 공격 가능성

- 대응 방안

을 최신 정보를 기준으로 분석해주세요.

"""

        return prompt