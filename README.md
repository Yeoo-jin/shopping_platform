# Tiny Second-hand Shopping Platform

시큐어 코딩을 적용한 Flask 기반 중고거래 플랫폼입니다.

- Public repository: <https://github.com/Yeoo-jin/shopping_platform>

## 요구사항 분석

| 요구사항 | 구현 내용 |
|---|---|
| 회원 및 프로필 관리 | 회원가입, 로그인·로그아웃, 소개글·비밀번호 변경 |
| 상품 등록 및 관리 | 이미지·제목·설명·가격 등록, 상세 조회, 검색, 수정·삭제 |
| 사용자 간 소통 | 상품별 WebSocket 1:1 채팅, 채팅 목록, 사용자 차단 |
| 악성 사용자·상품 대응 | 신고, 관리자 검토, 사용자·상품 차단 및 해제 |
| 사용자 간 송금 | 현재 비밀번호 재확인이 적용된 학습용 가상 포인트 전송 |
| 관리자 기능 | 사용자·상품·신고 및 보안 감사 로그 관리 |

## 시스템 설계

```text
브라우저
 ├─ HTTPS 요청 ───────────────┐
 └─ WebSocket(WSS) 채팅 ─────┤
                              ▼
                      Flask / Flask-SocketIO
                     ├─ 인증·권한·입력 검증
                     ├─ CSRF·Rate limiting
                     ├─ 상품·신고·포인트 서비스
                     └─ 감사 로그
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              SQLite 데이터베이스   비공개 이미지 저장소
```

서버는 모든 중요 입력과 권한을 다시 검증합니다. 상품 수정·삭제는 소유자 또는
관리자만 가능하고, 채팅방은 해당 상품의 판매자와 대화 상대만 접근할 수 있습니다.
포인트 변경은 하나의 데이터베이스 트랜잭션으로 처리합니다.

## 주요 기능

- 회원가입 / 로그인 / 로그아웃
- 마이페이지, 소개글 및 비밀번호 변경
- 상품 이미지 등록 / 상세 조회 / 수정 / 삭제
- 상품명 및 설명 검색
- 인증된 상품별 WebSocket 1:1 실시간 채팅
- 현재 비밀번호 재확인이 적용된 가상 포인트 전송
- 사용자 및 상품 신고
- 관리자 신고 검토, 사용자·상품 차단 관리

## 보안 적용 사항

- 비밀번호 평문 저장 금지: Werkzeug의 scrypt 기반 솔트 해시 사용
- SQL Injection 방지: 모든 입력에 SQLite 파라미터 바인딩 사용
- CSRF 방지: Flask-WTF CSRF 토큰 적용
- XSS 방지: Jinja2 자동 이스케이프 사용
- 접근 제어: 상품 수정·삭제 시 소유자 및 관리자 권한 확인
- 세션 보호: HttpOnly, SameSite=Lax 설정
- 로그인·회원가입·채팅·신고 요청 속도 제한
- 포인트 전송 일회성 토큰, 전송 한도, 트랜잭션 및 감사 로그
- CSP, 클릭재킹 방지, MIME 스니핑 방지 등 보안 헤더
- 이미지 실제 디코딩·해상도 제한·WEBP 재인코딩
- 입력값 검증: 길이, 자료형, 범위 검증
- 관리자 기능 분리 및 일반 사용자 접근 차단
- 관리자 조치·비밀번호 변경·채팅 차단 등 보안 감사 로그
- 오류 발생 시 내부 스택 트레이스 비노출(debug=False)

## 확인된 보안 약점과 개선 내용

| 기존 약점 | 개선 내용 |
|---|---|
| 코드에 기본 관리자 계정과 비밀번호 포함 | 하드코딩 제거, 기존 자격 증명 무효화, CLI에서 비밀번호 비노출 생성 |
| 고정된 개발용 `SECRET_KEY` | 환경변수 사용 및 미설정 시 안전한 임의 키 생성 |
| 로그인·채팅·신고 반복 요청 가능 | 기능별 서버 측 Rate limiting 적용 |
| 새 비밀번호만 알면 비밀번호 변경 가능 | 현재 비밀번호 재확인 추가 |
| 확장자 위주의 이미지 확인 | Pillow 디코딩, 픽셀 제한, WEBP 재인코딩, 임의 파일명 사용 |
| 업로드 파일을 정적 디렉터리에서 직접 제공 | 웹 루트 외부 저장 및 검증된 전용 라우트로 제공 |
| 페이지 갱신 기반 채팅 | 인증된 Socket.IO 채널과 서버 측 방 권한 검사 적용 |
| 한 사용자가 상대방 채팅 기록까지 삭제 | 메시지는 보존하고 요청 사용자 목록에서만 숨김 처리 |
| 포인트 중복 전송·재전송 가능성 | 재인증, 일회성 토큰, 한도, 트랜잭션, 감사 로그 적용 |
| 신고 누적만으로 자동 차단 | 중복·횟수 제한과 관리자 검토 상태로 변경 |
| 보안 응답 헤더 부족 | CSP, HSTS, `nosniff`, frame 차단, Referrer·Permissions 정책 적용 |
| 내부 오류 노출 가능성 | 전용 403·404·500 페이지와 `debug=False` 적용 |

## 실행 환경

- Ubuntu / WSL 권장
- Python 3.10 이상

## 실행 방법

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

브라우저에서 아래 주소로 접속합니다.

```text
http://127.0.0.1:5000
```

## 관리자 계정 생성

코드에 기본 관리자 비밀번호를 포함하지 않습니다. 최초 실행 후 아래 명령으로
관리자를 생성하세요. 비밀번호는 화면에 표시되지 않으며 12자 이상이어야 합니다.

```bash
export FLASK_APP=app.py
flask create-admin 원하는관리자아이디
```

과거 샘플 관리자 자격 증명은 보안 마이그레이션에서 자동으로 무효화됩니다.
운영 환경에서는 고정된 임의 `SECRET_KEY`와 HTTPS를 사용하고 `COOKIE_SECURE=1`을
설정해야 합니다.

## 프로젝트 구조

```text
shopping_platform/
├── app.py
├── requirements.txt
├── README.md
├── deployment/
│   └── nginx.conf
├── static/
│   ├── style.css
│   └── socket.io.min.js
├── uploads/                 # 실행 중 생성, 웹 루트 외부 이미지
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── product_new.html
    ├── product_detail.html
    ├── product_edit.html
    ├── chat.html
    ├── chat_room.html
    ├── transfer.html
    ├── mypage.html
    ├── report.html
    ├── admin.html
    └── error.html
```

## 테스트 체크리스트

| 구분 | 테스트 항목 | 결과 |
|---|---|---|
| 회원 | 회원가입 및 중복 아이디 차단 | 통과 |
| 인증 | 올바른 계정 로그인 및 로그아웃 | 통과 |
| 상품 | 상품 등록·조회·수정·삭제 | 통과 |
| 권한 | 타 사용자 상품 수정·삭제 차단 | 통과 |
| 검색 | 제목·설명 키워드 검색 | 통과 |
| 채팅 | 인증된 WebSocket 상품별 1:1 메시지 | 통과 |
| 채팅 | 메시지 검증·속도 제한·사용자 차단 | 통과 |
| 포인트 | 재인증·한도·중복 방지·트랜잭션 | 통과 |
| 신고 | 중복·횟수 제한 및 관리자 검토 상태 | 통과 |
| 관리자 | 사용자·상품 차단 전환 및 감사 로그 | 통과 |
| 보안 | CSRF 토큰 없는 POST 요청 차단 | 통과 |
| 보안 | SQL Injection 문자열 입력 시 쿼리 구조 미변경 | 통과 |
| 보안 | HTML 태그 입력 시 화면에서 이스케이프 | 통과 |

## AI 도구 활용

요구사항 분석, 보안 체크리스트 정리, Flask·SQLite 구현 보조, WebSocket 채팅
구조 설계, 테스트 케이스 작성, 오류 원인 분석과 README 작성에 OpenAI Codex
(ChatGPT 기반 도구)를 적극적으로 활용했습니다. AI가 제안한 코드는 그대로
신뢰하지 않고 로컬 테스트 클라이언트, Socket.IO 테스트 클라이언트, 데이터베이스
무결성 검사 및 수동 기능 확인을 통해 검증했습니다.

## 알려진 한계 및 유지보수 계획

- 현재는 학습용 SQLite를 사용하므로 실제 서비스에서는 PostgreSQL 등으로 교체해야 합니다.
- 채팅은 Flask-SocketIO WebSocket을 사용합니다. 다중 서버 운영 시 Redis 메시지 큐와 sticky session을 추가해야 합니다.
- 신고는 자동 차단하지 않으며 관리자가 사용자 관리 화면에서 검토 후 처리합니다.
- 포인트는 실제 화폐가 아닌 학습용 데이터입니다. 실제 결제에는 검증된 결제대행사와 에스크로를 사용해야 합니다.

## HTTPS/WSS 운영 배포

운영 환경에서는 고정된 비밀키와 Secure 쿠키를 설정하고 Gunicorn을 실행합니다.

```bash
export SECRET_KEY="충분히 긴 운영용 임의 문자열"
export COOKIE_SECURE=1
gunicorn --workers 1 --threads 100 --bind 127.0.0.1:5000 app:app
```

앞단의 Nginx에는 TLS 인증서를 적용하고 일반 요청과 `/socket.io/` 요청을
`127.0.0.1:5000`으로 프록시합니다. 예시는
[`deployment/nginx.conf`](deployment/nginx.conf)에 있습니다. HTTPS 페이지에서
Socket.IO 클라이언트는 자동으로 암호화된 `wss://` 연결을 사용합니다.
