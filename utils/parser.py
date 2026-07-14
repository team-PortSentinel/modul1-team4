# Nmap 텍스트 파싱 및 정제 모듈
# 예시 
import csv
import json
from datetime import datetime

class NmapParser:
    def __init__(self, scan_data):
        """
        nm.scan() 실행 결과인 딕셔너리 데이터를 전달받습니다.
        """
        self.scan_data = scan_data

    def display_terminal(self):
        """
        스캔 결과를 터미널에 보기 좋게 표 형태로 출력합니다.
        """
        print("\n" + "=" * 80)
        print("                      NMAP 스캔 결과 리포트")
        print("=" * 80)

        # 결과 데이터에 호스트가 없는 경우
        if not self.scan_data or 'scan' not in self.scan_data or not self.scan_data['scan']:
            print("[-] 파싱할 스캔 결과가 존재하지 않거나 호스트가 오프라인 상태입니다.")
            return

        for host_ip, host_info in self.scan_data['scan'].items():
            # 기본 호스트 정보 파싱
            hostname = host_info.get('hostnames', [{}])[0].get('name', 'N/A')
            state = host_info.get('status', {}).get('state', 'unknown')
            
            print(f"\n[ Host: {host_ip} ({hostname}) ] - 상태: {state.upper()}")
            
            # 운영체제(OS) 예측 정보가 있을 경우 출력
            if 'osmatch' in host_info and host_info['osmatch']:
                os_name = host_info['osmatch'][0].get('name', '알 수 없음')
                accuracy = host_info['osmatch'][0].get('accuracy', '0')
                print(f"👉 예상 OS: {os_name} (정확도: {accuracy}%)")
            
            # 포트 정보 파싱
            protocols = ['tcp', 'udp']
            has_ports = False

            for proto in protocols:
                if proto in host_info:
                    has_ports = True
                    print(f"\n  * 프로토콜: {proto.upper()}")
                    print(f"    {'포트(PORT)':<12} {'상태(STATE)':<12} {'서비스(SERVICE)':<18} {'버전 정보(VERSION)'}")
                    print("    " + "-" * 70)
                    
                    ports = host_info[proto]
                    for port, port_info in sorted(ports.items()):
                        port_str = f"{port}/{proto}"
                        port_state = port_info.get('state', 'unknown')
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        extrainfo = port_info.get('extrainfo', '')
                        
                        # 제품명과 버전을 합쳐서 출력
                        version_details = f"{product} {version} {extrainfo}".strip() or "정보 없음"
                        
                        # 포트 상태에 따른 색상 구분 (터미널 지원 시)
                        if port_state == 'open':
                            state_colored = f"\033[92m{port_state:<12}\033[0m"  # 초록색
                        else:
                            state_colored = f"{port_state:<12}"

                        print(f"    {port_str:<12} {state_colored} {service:<18} {version_details}")
            
            if not has_ports:
                print("  [-] 열려 있는 포트나 발견된 서비스 프로토콜이 없습니다.")
                
        print("\n" + "=" * 80)

    def export_to_csv(self, filename="scan_report.csv"):
        """
        파싱한 결과를 CSV 파일로 내보냅니다. (엑셀 등에서 열어보기 용이)
        """
        if not self.scan_data or 'scan' not in self.scan_data or not self.scan_data['scan']:
            print("[-] 내보낼 데이터가 없습니다.")
            return

        # CSV 헤더 설정
        fields = ['IP Address', 'Hostname', 'Protocol', 'Port', 'State', 'Service', 'Product', 'Version']
        
        try:
            with open(filename, mode='w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(fields)  # 헤더 작성
                
                for host_ip, host_info in self.scan_data['scan'].items():
                    hostname = host_info.get('hostnames', [{}])[0].get('name', 'N/A')
                    
                    for proto in ['tcp', 'udp']:
                        if proto in host_info:
                            for port, port_info in host_info[proto].items():
                                writer.writerow([
                                    host_ip,
                                    hostname,
                                    proto.upper(),
                                    port,
                                    port_info.get('state', ''),
                                    port_info.get('name', ''),
                                    port_info.get('product', ''),
                                    port_info.get('version', '')
                                ])
            print(f"[+] CSV 리포트 저장 완료: {filename}")
        except Exception as e:
            print(f"[-] CSV 저장 중 오류 발생: {e}")

    def export_to_json(self, filename="scan_report.json"):
        """
        필요 시 가공된 원본 JSON 형식으로 저장합니다.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.scan_data, f, indent=4, ensure_ascii=False)
            print(f"[+] JSON 원본 데이터 저장 완료: {filename}")
        except Exception as e:
            print(f"[-] JSON 저장 중 오류 발생: {e}")