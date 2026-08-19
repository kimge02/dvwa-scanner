# -*- coding: utf-8 -*-
"""
CSRF 취약점 탐지

DVWA의 비밀번호 변경 기능은 low 레벨에서 user_token 검증을
전혀 하지 않는다. 즉 공격자가 만든 악성 링크를 로그인된
사용자가 클릭하기만 해도 비밀번호가 강제로 바뀔 수 있다.

탐지 방법: user_token 없이 요청을 보내서, 그래도 성공(비밀번호 변경됨)
하는지 확인. 성공하면 CSRF 방어가 없는 것.
"""


def scan_csrf(session, base_url, security_level):
    url = f"{base_url}/vulnerabilities/csrf/"

    # 원래 비밀번호로 그대로 재설정 시도 (계정 상태가 안 바뀌게, 안전하게)
    # user_token은 의도적으로 넣지 않음
    params = {
        "password_new": "password",
        "password_conf": "password",
        "Change": "Change",
    }

    resp = session.get(url, params=params)

    detected = "Password Changed" in resp.text

    return {
        "security_level": security_level,
        "vuln_type": "CSRF",
        "category": "password_change",
        "payload": "user_token 누락 상태로 비밀번호 변경 요청",
        "url": url,
        "detected": detected,
        "detail": (
            "user_token 검증 없이 비밀번호 변경 성공 -> CSRF 취약"
            if detected else
            "user_token 검증됨 -> CSRF 방어 작동"
        ),
    } 
