# Nmap 텍스트 파싱 및 정제 모듈
# 예시 
import json

class NmapParser:
    def __init__(self, scan_data):
        """
        nm.scan() 실행 결과인 원본 딕셔너리 데이터를 전달받습니다.
        """
        self.scan_data = scan_data

    def to_dict(self):
        """
        Nmap 원본 데이터를 가공하여 직관적인 '파이썬 딕셔너리' 형태로 반환합니다.
        """
        parsed_result = {
            "success": False,
            "hosts": []
        }

        # 데이터가 비어있거나 올바르지 않은 경우 빈 구조 반환
        if not self.scan_data or 'scan' not in self.scan_data or not self.scan_data['scan']:
            return parsed_result

        parsed_result["success"] = True

        for host_ip, host_info in self.scan_data['scan'].items():
            hostname = host_info.get('hostnames', [{}])[0].get('name', 'N/A')
            state = host_info.get('status', {}).get('state', 'unknown')
            
            # 예상 OS 정보 파싱
            os_name = "unknown"
            os_accuracy = 0
            if 'osmatch' in host_info and host_info['osmatch']:
                os_name = host_info['osmatch'][0].get('name', 'unknown')
                os_accuracy = int(host_info['osmatch'][0].get('accuracy', 0))

            host_data = {
                "ip": host_ip,
                "hostname": hostname,
                "status": state,
                "os": {
                    "name": os_name,
                    "accuracy": os_accuracy
                },
                "ports": []  # 이 호스트에서 발견된 포트 목록
            }

            # TCP / UDP 포트 데이터 정리
            for proto in ['tcp', 'udp']:
                if proto in host_info:
                    ports = host_info[proto]
                    for port, port_info in sorted(ports.items()):
                        host_data["ports"].append({
                            "port": port,
                            "protocol": proto.upper(),
                            "state": port_info.get('state', 'unknown'),
                            "service": port_info.get('name', 'unknown'),
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', ''),
                            "extrainfo": port_info.get('extrainfo', '')
                        })
            
            parsed_result["hosts"].append(host_data)

        return parsed_result

    def to_json(self):
        """
        가공된 딕셔너리 결과를 API 전송에 적합한 'JSON 문자열' 형태로 반환합니다.
        """
        dict_data = self.to_dict()
        # 한글 깨짐 방지 및 보기 좋게 정렬된 JSON 스트링 반환
        return json.dumps(dict_data, ensure_ascii=False, indent=4)