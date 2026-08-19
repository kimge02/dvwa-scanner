# -*- coding: utf-8 -*-
"""
File Upload 취약점 탐지

DVWA의 업로드 페이지는 이미지만 허용한다고 되어있지만,
확장자 검증이 부실하면 .php 같은 실행 가능한 파일도 올라갈 수 있다.

안전을 위해 실제 공격 코드(웹셸)가 아닌, 단순 텍스트만 출력하는
무해한 php 파일로 "업로드 자체가 허용되는지"만 확인한다.
"""

UPLOAD_FILENAME = "upload_test.php"
UPLOAD_CONTENT = b"<?php echo 'upload_test_marker_ok'; ?>"


def scan_file_upload(session, base_url, security_level):
    url = f"{base_url}/vulnerabilities/upload/"

    files = {
        "uploaded": (UPLOAD_FILENAME, UPLOAD_CONTENT, "application/x-php"),
    }
    data = {"Upload": "Upload"}

    resp = session.post(url, data=data, files=files)

    # 업로드 성공 시 DVWA는 저장 경로를 응답에 표시함
    detected = "succesfully" in resp.text.lower() or "successfully" in resp.text.lower()

    return {
        "security_level": security_level,
        "vuln_type": "File Upload",
        "category": "unrestricted_extension",
        "payload": f"{UPLOAD_FILENAME} (php 확장자 파일 업로드 시도)",
        "url": url,
        "detected": detected,
        "detail": (
            ".php 확장자 파일 업로드 허용됨 -> 취약"
            if detected else
            "업로드 차단됨 -> 방어 작동"
        ),
    }
