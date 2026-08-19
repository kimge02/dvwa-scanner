# -*- coding: utf-8 -*-
"""
DVWA 취약점 자동 스캐너 (개선판)
"""

import time
import requests
from bs4 import BeautifulSoup

from config import BASE_URL, LOGIN_CREDS, SECURITY_LEVELS, SQLI_PAYLOADS, XSS_PAYLOADS
from csrf_module import scan_csrf
from command_injection_module import scan_command_injection
from file_inclusion_module import scan_file_inclusion
from file_upload_module import scan_file_upload

class DVWAScanner:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []

    def login(self):
        login_page = self.session.get(f"{self.base_url}/login.php")
        soup = BeautifulSoup(login_page.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input.get("value") if token_input else ""

        data = dict(LOGIN_CREDS)
        data["user_token"] = token
        resp = self.session.post(f"{self.base_url}/login.php", data=data)

        if "Login failed" in resp.text:
            raise RuntimeError("로그인 실패 - 계정 정보 확인 필요")
        print("[+] 로그인 성공")

    def set_security_level(self, level):
        sec_page = self.session.get(f"{self.base_url}/security.php")
        soup = BeautifulSoup(sec_page.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input.get("value") if token_input else ""

        data = {"security": level, "seclev_submit": "Submit", "user_token": token}
        self.session.post(f"{self.base_url}/security.php", data=data)
        print(f"[+] 보안 레벨 설정: {level}")

    def scan_sqli(self, security_level):
        url = f"{self.base_url}/vulnerabilities/sqli/"

        for category, payloads in SQLI_PAYLOADS.items():
            for payload in payloads:
                start = time.time()
                try:
                    resp = self.session.get(
                        url, params={"id": payload, "Submit": "Submit"}, timeout=15
                    )
                except requests.exceptions.Timeout:
                    resp = None
                elapsed = time.time() - start

                if category == "time_based_blind":
                    detected = elapsed >= 2.5
                    detail = f"응답시간 {elapsed:.2f}s"
                else:
                    detected = resp is not None and "First name" in resp.text
                    detail = "정상 응답에 데이터 반환됨" if detected else "데이터 미반환"

                self.results.append({
                    "security_level": security_level,
                    "vuln_type": "SQLi",
                    "category": category,
                    "payload": payload,
                    "url": url,
                    "detected": detected,
                    "detail": detail,
                })

    def scan_xss(self, security_level):
        url = f"{self.base_url}/vulnerabilities/xss_r/"

        for payload in XSS_PAYLOADS:
            resp = self.session.get(url, params={"name": payload})
            detected = payload in resp.text

            self.results.append({
                "security_level": security_level,
                "vuln_type": "XSS",
                "category": "reflected",
                "payload": payload,
                "url": url,
                "detected": detected,
                "detail": "payload가 응답에 그대로 반사됨" if detected else "필터링되거나 반사 안 됨",
            })

    def run_full_scan(self, levels=None):
        levels = levels or SECURITY_LEVELS
        self.login()

        for level in levels:
            print(f"\n{'='*50}\n[보안 레벨: {level}] 스캔 시작\n{'='*50}")
            self.set_security_level(level)
            self.scan_sqli(level)
            self.scan_xss(level)
            self.results.append(scan_csrf(self.session, self.base_url, level))
            self.results.extend(scan_command_injection(self.session, self.base_url, level))
            self.results.extend(scan_file_inclusion(self.session, self.base_url, level))
            self.results.append(scan_file_upload(self.session, self.base_url, level))

        return self.results

    def summary(self):
        from collections import defaultdict

        counts = defaultdict(lambda: {"total": 0, "detected": 0})
        for r in self.results:
            key = (r["security_level"], r["vuln_type"])
            counts[key]["total"] += 1
            if r["detected"]:
                counts[key]["detected"] += 1

        print(f"\n{'='*60}\n요약: 보안 레벨별 탐지 결과\n{'='*60}")
        print(f"{'보안레벨':<10}{'취약점':<10}{'탐지/전체':<15}")
        for (level, vuln_type), c in sorted(counts.items()):
            print(f"{level:<10}{vuln_type:<10}{c['detected']}/{c['total']}")


if __name__ == "__main__":
    scanner = DVWAScanner()
    scanner.run_full_scan()
    scanner.summary()

    import json
    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(scanner.results, f, ensure_ascii=False, indent=2)
    print("\n[+] 상세 결과 저장: scan_results.json")
