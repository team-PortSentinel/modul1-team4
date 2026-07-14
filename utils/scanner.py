import nmap
import sys

def nmap_scanner():
    # 1. Nmap 스캐너 객체 초기화
    nm = nmap.PortScanner()
    
    print("=" * 50)
    print("          파이썬 Nmap 포트 스캐너")
    print("=" * 50)
    # 2. 사용자 입력 받기
    target = input("스캔할 대상 IP 또는 도메인을 입력하세요 (예: 127.0.0.1): ").strip()
    ports = input("스캔할 포트 범위를 입력하세요 (예: 22-80 또는 80): ").strip()
    
    if not target:
        print("[-] 오류: 대상 IP/도메인을 입력해야 합니다.")
        sys.exit(1)
        
    print(f"\n[+] {target} 대상으로 포트 {ports} 스캔을 시작합니다...")
    
    try:
        # 3. 스캔 실행 (-v: 상세히 출력, -sV: 서비스 버전 감지)
        # 중요: 상세 스캔(서비스 버전, OS 감지 등)은 관리자 권한(sudo)이 필요할 수 있습니다.
        scan_results = nm.scan(hosts=target, ports=ports, arguments='-v -sV')
        
    except nmap.PortScannerError as e:
        print(f"[-] Nmap 실행 중 오류가 발생했습니다: {e}")
        print("[!] 시스템에 Nmap이 올바르게 설치되어 있고, 환경 변수(Path)가 등록되어 있는지 확인하세요.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 알 수 없는 오류 발생: {e}")
        sys.exit(1)

    # 4. 결과 분석 및 출력
    for host in nm.all_hosts():
        print(f"\n[ Host : {host} ({nm[host].hostname()}) ]")
        print(f"상태 (State) : {nm[host].state()}")
        
        # TCP 프로토콜 결과 파싱
        for proto in nm[host].all_protocols():
            print(f"프로토콜 : {proto.upper()}")
            
            lport = sorted(nm[host][proto].keys())
            print(f"{'포트':<8} {'상태':<8} {'서비스 이름':<15} {'버전 정보'}")
            print("-" * 60)
            
            for port in lport:
                port_data = nm[host][proto][port]
                state = port_data['state']
                service = port_data['name']
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                
                version_info = f"{product} {version}".strip() or "알 수 없음"
                
                # 열린 포트 위주로 시각적으로 강조
                if state == 'open':
                    status_display = f"\033[92m{state:<8}\033[0m"  # 초록색 표시 (터미널 지원 시)
                else:
                    status_display = f"{state:<8}"
                    
                print(f"{port:<8} {status_display} {service:<15} {version_info}")
                
    print("\n[+] 스캔이 완료되었습니다.")

if __name__ == "__main__":
    nmap_scanner()