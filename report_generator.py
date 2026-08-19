# -*- coding: utf-8 -*-
"""
스캔 결과(scan_results.json)를 읽어서, 보기 좋은 HTML 리포트로 변환한다.
"""

import json
import html


def generate_html_report(results, output_path="report.html"):
    # 보안 레벨별로 그룹화
    levels = ["low", "medium", "high"]

    html_parts = ["""
<html>
<head>
<meta charset="utf-8">
<title>DVWA Vulnerability Scan Report</title>
<style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
    h1 { color: #222; }
    h2 { color: #333; border-bottom: 2px solid #ccc; padding-bottom: 5px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 30px; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; }
    th { background: #333; color: white; }
    .success { background: #ffe0e0; color: #a00; font-weight: bold; }
    .fail { background: #e0ffe0; color: #060; }
    .summary { display: flex; gap: 20px; margin-bottom: 30px; }
    .summary-box { background: white; border-radius: 8px; padding: 15px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
</style>
</head>
<body>
<h1>DVWA 취약점 스캔 리포트</h1>
"""]

    for level in levels:
        level_results = [r for r in results if r["security_level"] == level]
        if not level_results:
            continue

        vuln_count = sum(1 for r in level_results if r["detected"])
        total = len(level_results)

        html_parts.append(f'<h2>보안 레벨: {level.upper()} (취약점 {vuln_count}/{total}건 발견)</h2>')
        html_parts.append('<table><tr><th>종류</th><th>Payload</th><th>결과</th><th>상세</th></tr>')

        for r in level_results:
            css_class = "success" if r["detected"] else "fail"
            status = "취약점 발견" if r["detected"] else "안전"
            html_parts.append(
                f'<tr class="{css_class}">'
                f'<td>{html.escape(r["vuln_type"])}</td>'
                f'<td>{html.escape(str(r["payload"]))}</td>'
                f'<td>{status}</td>'
                f'<td>{html.escape(r["detail"])}</td>'
                f'</tr>'
            )
        html_parts.append('</table>')

    html_parts.append('</body></html>')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("".join(html_parts))

    print(f"[+] HTML 리포트 생성 완료: {output_path}")


if __name__ == "__main__":
    with open("scan_results.json", encoding="utf-8") as f:
        results = json.load(f)
    generate_html_report(results)
