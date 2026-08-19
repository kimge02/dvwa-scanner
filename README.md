# DVWA 기반 웹 취약점 자동 탐지 시스템

DVWA(Damn Vulnerable Web Application)를 대상으로 SQL Injection, XSS, Command
Injection, File Inclusion, CSRF, File Upload 6종 취약점을 자동으로 스캔하고,
DVWA의 보안 레벨(Low/Medium/High)별 방어 효과를 비교 분석하는 도구.

26학년도 1학기 산학캡스톤디자인 프로젝트(안유정, 김고은, 박주영)로 시작했으며,
발표 이후 개인적으로 코드를 재검토하고 대폭 확장했다.

## 원본 대비 개선한 점

원본(발표본)은 SQLi/XSS 2종만 다뤘고, 실제로 테스트해보니
버그가 있었다. 다시 열어보면서 다음을 개선했다.

### 버그 수정
- **SQLi payload 문법 오류**: MySQL의 `--` 주석은 뒤에 공백이 있어야 정상적으로
  인식된다. 원본 payload(`' OR 1=1 --`)는 공백이 없어 실제로는 매번 SQL 문법
  에러가 나서 탐지에 실패하고 있었다. 공백을 추가해 정상 동작하도록 수정.
- **UNION-based payload 컬럼 수 불일치**: DVWA `users` 테이블은 2개 컬럼을
  SELECT하는데, 원본 payload는 컬럼 1개(`UNION SELECT null`)만 지정해 항상
  실패했다. `UNION SELECT null,null`로 수정.
- **Time-based blind SQLi 판별 방식**: `sleep()` payload는 텍스트 비교로는
  검증할 수 없다. 응답 시간을 측정해 실제로 지연이 발생했는지로 판별하도록 변경.

### 기능 확장
발표 시점 "향후 계획"이었던 CSRF·File Upload 탐지를 구현했고, 추가로
Command Injection·File Inclusion도 새로 추가해 총 6종의 취약점을 다룬다.

- **보안 레벨별 자동 반복 스캔**: 원본은 단일 레벨에서만 테스트했다. Low/Medium/
  High 3단계를 자동으로 전환하며 동일 payload를 반복 실행해, 보안 레벨에 따른
  방어 효과를 정량적으로 비교할 수 있게 했다.

## 취약점별 탐지 방법

| 취약점 | 탐지 방법 |
|---|---|
| SQL Injection | 에러 기반, Always-true, UNION 기반, Time-based blind |
| XSS (Reflected) | Payload가 응답에 그대로 반사되는지 확인 |
| Command Injection | `;`, `&&`, `\|`, 개행(`\n`) 등 다양한 구분자로 명령어 삽입 시도 |
| File Inclusion | Path Traversal로 `/etc/passwd` 등 서버 파일 읽기 시도 |
| CSRF | `user_token` 없이 비밀번호 변경 요청이 성공하는지 확인 |
| File Upload | `.php` 확장자 파일 업로드가 허용되는지 확인 (무해한 마커 파일 사용) |

## 실행 결과 (보안 레벨별 탐지 건수)

| 취약점 | Low | Medium | High |
|---|---|---|---|
| SQL Injection | 10/14 | 0/14 | 0/14 |
| XSS | 5/5 | 3/5 | 3/5 |
| Command Injection | 4/4 | 2/4 | 1/4 |
| File Inclusion | 2/4 | 2/4 | 0/4 |
| CSRF | 1/1 | 0/1 | 0/1 |
| File Upload | 1/1 | 0/1 | 0/1 |

## 결과 분석

- **CSRF, File Upload**는 Low에서만 뚫리고 Medium부터 완전히 막힌다 — 이진법적
  방어(토큰 검증 유무, 확장자 검증 유무)라 중간 단계가 없다.
- **SQL Injection**은 Low→Medium에서 급격히 막힌다. `mysqli_real_escape_string()`
  적용으로 작은따옴표가 이스케이프되면서 대부분의 payload가 한 번에 무력화된다.
- **XSS**는 Medium 이후로도 일부(3/5)가 계속 뚫린다. `<script>` 태그 문자열만
  걸러내는 블랙리스트 방식이라, `<svg onload=...>`처럼 script 태그를 쓰지 않는
  payload는 High 레벨까지도 필터를 통과한다.
- **Command Injection**은 High에서도 1개가 뚫린다. Low→Medium에서 `;`와 `&&`가
  막히고, Medium→High에서 `|`가 추가로 막히지만, **개행 문자(`\n`)를 이용한
  명령어 삽입은 High까지도 막지 못했다.** 이는 블랙리스트 방식 필터가 아무리
  정교해져도 개발자가 예상하지 못한 우회 벡터가 항상 존재할 수 있음을 보여준다.
- **File Inclusion**은 Low와 Medium에서 탐지 건수가 동일(2/4)하다는 점이
  흥미롭다 — Medium 레벨의 방어가 이 프로젝트가 시도한 특정 payload 패턴에는
  효과가 없었고, High에서야 완전히 막혔다.

## 파일 구조

```
config.py                     # 대상 URL, 로그인 정보, payload 목록
scanner.py                    # 메인 스캐너 클래스 (로그인, 보안레벨 전환, 결과 통합)
csrf_module.py                # CSRF 탐지
command_injection_module.py   # Command Injection 탐지
file_inclusion_module.py      # File Inclusion(LFI) 탐지
file_upload_module.py         # File Upload 탐지
report_generator.py           # HTML 리포트 생성
docker-compose.yml            # DVWA 실습 환경 (Docker)
```

## 실행 방법

```bash
# 1. DVWA 실행
docker compose up -d
# http://localhost:8080 접속 → Create/Reset Database → admin/password로 로그인

# 2. 패키지 설치
pip install requests beautifulsoup4

# 3. 스캔 실행 (Low/Medium/High 자동 반복)
python3 scanner.py

# 4. HTML 리포트 생성
python3 report_generator.py
```

## 배운 점

- 발표 당시엔 몰랐던 SQLi payload의 문법 오류(주석 처리 공백 문제)를 재검토
  과정에서 발견하고 수정했다. "결과가 이상하게 나온다"는 걸 그냥 넘기지 않고
  근본 원인을 추적하는 과정에서 MySQL 주석 문법에 대해 제대로 이해하게 됐다.
- 보안 레벨별로 반복 실험하며, 필터가 "얼마나 안전한가"뿐 아니라 "어떤 방식으로
  안전해지는가"(한 번에 완전히 막히는지, 점진적으로 막히는지, 끝까지 구멍이
  남는지)가 취약점 종류마다 다르다는 걸 데이터로 확인했다.
- 블랙리스트 기반 필터링의 근본적 한계(XSS, Command Injection에서 공통적으로
  관찰)를 실증적으로 보여줄 수 있었다.
