# LICA-SSO

OAuth 2.0 / OpenID Connect 기반의 SSO(Single Sign-On) 인증 서버 프로젝트.

Spring Boot 기반 모듈형 템플릿 위에 표준 SSO 기능을 구현합니다.

## SSO 서비스 기능 스펙

### 1. 인증 프로토콜

#### 1.1 OAuth 2.0 (RFC 6749)

**프로토콜 엔드포인트:**

| 엔드포인트 | 설명 | 표준 |
|-----------|------|------|
| `GET /oauth2/authorize` | Authorization Endpoint | [RFC 6749 §3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1) |
| `POST /oauth2/token` | Token Endpoint | [RFC 6749 §3.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2) |
| `POST /oauth2/revoke` | Token Revocation | [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) |
| `POST /oauth2/introspect` | Token Introspection | [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) |
| `POST /oauth2/device_authorization` | Device Authorization | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) |
| `GET /.well-known/oauth-authorization-server` | Authorization Server Metadata | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) |

**지원 Grant Types:**

| Grant Type | `grant_type` 값 | 표준 | 우선순위 |
|------------|-----------------|------|---------|
| Authorization Code + PKCE | `authorization_code` + `code_verifier` | [RFC 6749 §4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | 필수 |
| Client Credentials | `client_credentials` | [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) | 필수 |
| Refresh Token | `refresh_token` | [RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6) | 필수 |
| Device Code | `urn:ietf:params:oauth:grant-type:device_code` | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | 선택 |
| Token Exchange | `urn:ietf:params:oauth:grant-type:token-exchange` | [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | 선택 |

> **참고:** Implicit Grant와 Resource Owner Password Credentials는 OAuth 2.1에서 제거되었으므로 구현하지 않습니다.

**클라이언트 인증 방법 (Token Endpoint):**

| 방법 | 설명 | 표준 |
|-----|------|------|
| `client_secret_basic` | HTTP Basic Auth (client_id:client_secret) | RFC 6749 §2.3.1 |
| `client_secret_post` | Request Body에 포함 | RFC 6749 §2.3.1 |
| `client_secret_jwt` | HMAC 서명 JWT | [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) |
| `private_key_jwt` | 클라이언트 개인키 서명 JWT | [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) |
| `none` | 인증 없음 (Public 클라이언트, PKCE 필수) | RFC 6749 §2.1 |

#### 1.2 OpenID Connect 1.0 (OIDC)

**추가 엔드포인트:**

| 엔드포인트 | 설명 | 표준 |
|-----------|------|------|
| `GET /userinfo` | 인증된 사용자 정보 반환 | [OIDC Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) |
| `GET /.well-known/openid-configuration` | OIDC Discovery 메타데이터 | [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
| `GET /oauth2/jwks` | JSON Web Key Set | [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) |
| `POST /oauth2/register` | Dynamic Client Registration | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) |
| `GET /oauth2/logout` | RP-Initiated Logout | [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) |

**표준 Scope:**

| Scope | 반환 클레임 |
|-------|-----------|
| `openid` | `sub` (OIDC 필수) |
| `profile` | `name`, `given_name`, `family_name`, `nickname`, `preferred_username`, `picture`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` |
| `phone` | `phone_number`, `phone_number_verified` |
| `offline_access` | Refresh Token 발급 허용 |

**OIDC Discovery 응답 예시 (`/.well-known/openid-configuration`):**

```json
{
  "issuer": "https://sso.example.com",
  "authorization_endpoint": "https://sso.example.com/oauth2/authorize",
  "token_endpoint": "https://sso.example.com/oauth2/token",
  "userinfo_endpoint": "https://sso.example.com/userinfo",
  "jwks_uri": "https://sso.example.com/oauth2/jwks",
  "registration_endpoint": "https://sso.example.com/oauth2/register",
  "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "revocation_endpoint": "https://sso.example.com/oauth2/revoke",
  "introspection_endpoint": "https://sso.example.com/oauth2/introspect",
  "end_session_endpoint": "https://sso.example.com/oauth2/logout",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

#### 1.3 SAML 2.0 (선택)

| 엔드포인트 | 설명 | 바인딩 |
|-----------|------|--------|
| `GET/POST /saml2/sso` | Single Sign-On Service | HTTP-Redirect, HTTP-POST |
| `GET/POST /saml2/slo` | Single Logout Service | HTTP-Redirect, HTTP-POST, SOAP |
| `GET /saml2/metadata` | IdP Metadata | XML |

> SAML 2.0은 레거시 엔터프라이즈 연동이 필요한 경우에만 구현합니다.

---

### 2. 토큰 관리

#### 2.1 토큰 유형

| 토큰 | 형식 | 용도 | 유효기간 | 표준 |
|-----|------|------|---------|------|
| Access Token | JWT (self-contained) | 리소스 접근 인가 | 5~60분 | [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) |
| Refresh Token | Opaque | Access Token 재발급 | 수 시간~수 일 | RFC 6749 §1.5 |
| ID Token | JWT | 사용자 인증 정보 전달 | 5~60분 | [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) |
| Authorization Code | Opaque | 토큰 교환용 일회성 코드 | 30초~10분 | RFC 6749 §4.1.2 |

#### 2.2 ID Token 클레임 (OIDC Core §2)

| 클레임 | 설명 | 필수 |
|-------|------|------|
| `iss` | Issuer (HTTPS URL) | 필수 |
| `sub` | Subject (고유 사용자 ID) | 필수 |
| `aud` | Audience (client_id) | 필수 |
| `exp` | 만료 시간 | 필수 |
| `iat` | 발급 시간 | 필수 |
| `auth_time` | 인증 시간 | 조건부 (`max_age` 요청 시) |
| `nonce` | Replay 방지 값 | 조건부 (요청에 포함 시) |
| `acr` | Authentication Context Class Reference | 선택 |
| `amr` | Authentication Methods References | 선택 |
| `at_hash` | Access Token 해시 | 조건부 (Hybrid Flow) |
| `sid` | Session ID | 선택 (Back-Channel Logout 용) |

#### 2.3 Access Token 클레임 (RFC 9068)

| 클레임 | 설명 |
|-------|------|
| `iss` | Authorization Server Issuer |
| `sub` | Subject (사용자 또는 클라이언트) |
| `aud` | Resource Server 식별자 |
| `exp` | 만료 시간 |
| `iat` | 발급 시간 |
| `jti` | 고유 토큰 식별자 |
| `client_id` | 토큰 요청 클라이언트 |
| `scope` | 부여된 스코프 (공백 구분) |

#### 2.4 Token Revocation (RFC 7009)

- `POST /oauth2/revoke` — `token` 파라미터로 토큰 무효화
- Refresh Token 무효화 시 연관된 Access Token도 함께 무효화
- 유효하지 않은 토큰에 대해서도 HTTP 200 응답 (토큰 정보 노출 방지)

#### 2.5 Token Introspection (RFC 7662)

- `POST /oauth2/introspect` — 토큰 활성 상태 및 메타데이터 조회
- 비활성 토큰: `{"active": false}` 반환
- 인가된 Resource Server/Client만 호출 가능

#### 2.6 토큰 보안

| 기능 | 설명 | 표준 |
|-----|------|------|
| Refresh Token Rotation | 사용 시마다 새 Refresh Token 발급, 이전 토큰 무효화 | [RFC 9700 §4.14.2](https://datatracker.ietf.org/doc/rfc9700/) |
| Replay Detection | 이미 사용된 Refresh Token 사용 시 전체 토큰 패밀리 무효화 | RFC 9700 |
| PKCE | Public 클라이언트 필수, Confidential 클라이언트 권장 | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) |
| DPoP | Sender-Constrained Token (소유 증명) | [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) |

---

### 3. 사용자 관리

#### 3.1 사용자 인증/계정 API

| 엔드포인트 | 메서드 | 설명 |
|-----------|-------|------|
| `/api/auth/register` | POST | 사용자 회원가입 |
| `/api/auth/verify-email` | GET/POST | 이메일 인증 (토큰 링크) |
| `/api/auth/login` | POST | 로컬 로그인 |
| `/api/auth/forgot-password` | POST | 비밀번호 재설정 요청 (이메일 발송) |
| `/api/auth/reset-password` | POST | 비밀번호 재설정 완료 |
| `/api/auth/change-password` | POST | 비밀번호 변경 (인증 필요, 현재 비밀번호 확인) |
| `/api/users/me` | GET | 내 프로필 조회 |
| `/api/users/me` | PUT | 내 프로필 수정 |
| `/api/users/me` | DELETE | 계정 삭제/비활성화 |

#### 3.2 비밀번호 정책

NIST SP 800-63B 및 OWASP 권장 사항 기준:

| 정책 | 권장값 | 근거 |
|-----|-------|------|
| 최소 길이 | 8자 (12자 이상 권장) | NIST SP 800-63B §5.1.1 |
| 최대 길이 | 64자 이상 허용 | NIST SP 800-63B |
| 문자 구성 규칙 | 강제하지 않음 (모든 유니코드 허용) | NIST SP 800-63B |
| 유출 비밀번호 검사 | HaveIBeenPwned 등 DB와 대조 | NIST SP 800-63B |
| 해싱 알고리즘 | bcrypt / Argon2id | OWASP Password Storage |
| 비밀번호 이력 | 최근 N개 재사용 금지 (예: 5~24개) | 엔터프라이즈 정책 |
| 주기적 만료 | 강제하지 않음 (유출 시에만 변경) | NIST SP 800-63B |

#### 3.3 SCIM 2.0 사용자 프로비저닝 (선택)

| 엔드포인트 | 설명 | 표준 |
|-----------|------|------|
| `/scim/v2/Users` | 사용자 CRUD | [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) |
| `/scim/v2/Groups` | 그룹 CRUD | RFC 7644 |
| `/scim/v2/Schemas` | 스키마 조회 | [RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643) |
| `/scim/v2/ServiceProviderConfig` | 서비스 설정 조회 | RFC 7644 |
| `/scim/v2/Bulk` | 벌크 작업 | RFC 7644 |

> SCIM은 외부 시스템(Azure AD, Okta 등)과의 사용자 자동 동기화가 필요한 경우 구현합니다.

---

### 4. 세션 관리

#### 4.1 SSO 세션

| 기능 | 설명 |
|-----|------|
| 세션 생성 | IdP에서 인증 성공 시 생성 |
| 세션 쿠키 | HttpOnly, Secure, SameSite=Lax; Opaque Session ID |
| 세션 저장소 | 서버 사이드 (Redis 권장) |
| Idle Timeout | 비활동 시 만료 (예: 30분) |
| Absolute Timeout | 활동 여부 무관 최대 수명 (예: 8~24시간) |
| Session Fixation 방지 | 인증 성공 후 Session ID 재생성 |
| 동시 세션 제한 | 사용자당 최대 동시 세션 수 제한 (초과 시 기존 세션 종료 또는 신규 거부) |
| Remember Me | 연장된 세션 수명 (민감한 작업 시 재인증 요구) |

#### 4.2 Single Logout (SLO)

| 메커니즘 | 설명 | 표준 |
|---------|------|------|
| RP-Initiated Logout | RP가 `GET /oauth2/logout`으로 세션 종료 요청 | [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) |
| Back-Channel Logout | OP가 각 RP의 `backchannel_logout_uri`로 Logout Token(JWT) 전송 | [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) |
| Front-Channel Logout | OP가 각 RP의 `frontchannel_logout_uri`를 hidden iframe으로 호출 | [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) |

**RP-Initiated Logout 파라미터:**

| 파라미터 | 필수 여부 | 설명 |
|---------|----------|------|
| `id_token_hint` | 권장 | 이전 발급된 ID Token |
| `client_id` | 선택 | id_token_hint 미제공 시 |
| `post_logout_redirect_uri` | 선택 | 로그아웃 후 리다이렉트 URI |
| `state` | 선택 | 리다이렉트 상태 값 |

**Back-Channel Logout Token 클레임:**

| 클레임 | 설명 |
|-------|------|
| `iss` | Issuer (ID Token과 동일) |
| `sub` | Subject |
| `aud` | Audience (RP의 client_id) |
| `iat` | 발급 시간 |
| `jti` | 고유 식별자 |
| `events` | `{"http://schemas.openid.net/event/backchannel-logout": {}}` 포함 필수 |
| `sid` | Session ID |

---

### 5. 다중 인증 (MFA)

#### 5.1 지원 인증 방법

| 방법 | 표준 | 설명 | 우선순위 |
|-----|------|------|---------|
| TOTP | [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) | Google Authenticator 등 시간 기반 OTP | 필수 |
| WebAuthn/FIDO2 | [W3C WebAuthn](https://www.w3.org/TR/webauthn-2/) | 하드웨어 보안키, 생체 인증, Passkey | 권장 |
| 이메일 OTP | - | 이메일로 일회용 코드 발송 | 선택 |
| SMS OTP | - | SMS로 일회용 코드 발송 (NIST에서 제한적 권장) | 선택 |
| 복구 코드 | - | 사전 생성된 일회용 백업 코드 | 필수 (MFA 등록 시) |

#### 5.2 MFA 엔드포인트

| 엔드포인트 | 메서드 | 설명 |
|-----------|-------|------|
| `/api/mfa/totp/setup` | POST | TOTP 등록 시작 (Secret + QR URI 반환) |
| `/api/mfa/totp/verify` | POST | TOTP 등록 완료 확인 |
| `/api/mfa/totp/validate` | POST | 로그인 시 TOTP 검증 |
| `/api/mfa/webauthn/register/options` | POST | WebAuthn 등록 옵션 (PublicKeyCredentialCreationOptions) |
| `/api/mfa/webauthn/register/verify` | POST | WebAuthn 등록 완료 |
| `/api/mfa/webauthn/authenticate/options` | POST | WebAuthn 인증 옵션 |
| `/api/mfa/webauthn/authenticate/verify` | POST | WebAuthn 인증 완료 |
| `/api/mfa/recovery-codes` | POST | 복구 코드 생성 |
| `/api/mfa/recovery-codes/verify` | POST | 복구 코드 검증 |
| `/api/mfa/methods` | GET | 등록된 MFA 방법 조회 |
| `/api/mfa/methods/{id}` | DELETE | MFA 방법 삭제 |

#### 5.3 TOTP 구현 사양 (RFC 6238)

| 항목 | 값 |
|-----|---|
| 알고리즘 | HMAC-SHA1 (SHA-256 권장) |
| 자릿수 | 6자리 |
| 주기 | 30초 |
| Secret 길이 | 최소 160비트 (20바이트) |
| 허용 오차 | ±1 스텝 |
| QR URI 형식 | `otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30` |

#### 5.4 MFA 정책

| 정책 | 설명 |
|-----|------|
| 적용 범위 | 전체 필수 / 선택 / 조건부 (글로벌 또는 Realm별 설정) |
| 조건부 MFA | 신규 디바이스, 새 위치, 비정상 시간대, 권한 상승 시 트리거 |
| Step-Up 인증 | 민감한 작업 시 추가 MFA 요구 (`acr_values` 활용) |

---

### 6. 클라이언트(애플리케이션) 관리

#### 6.1 Dynamic Client Registration (RFC 7591 / RFC 7592)

| 엔드포인트 | 메서드 | 설명 |
|-----------|-------|------|
| `/oauth2/register` | POST | 클라이언트 등록 |
| `/oauth2/register/{client_id}` | GET | 클라이언트 설정 조회 |
| `/oauth2/register/{client_id}` | PUT | 클라이언트 설정 수정 |
| `/oauth2/register/{client_id}` | DELETE | 클라이언트 삭제 |

#### 6.2 클라이언트 메타데이터

| 필드 | 설명 |
|-----|------|
| `client_name` | 클라이언트 표시 이름 |
| `redirect_uris` | 허용된 Redirect URI 목록 (필수) |
| `grant_types` | 사용할 Grant Type 목록 |
| `response_types` | 사용할 Response Type 목록 |
| `token_endpoint_auth_method` | Token Endpoint 인증 방법 |
| `scope` | 요청 가능한 스코프 (공백 구분) |
| `logo_uri` | 클라이언트 로고 URL |
| `client_uri` | 클라이언트 홈페이지 URL |
| `policy_uri` | 개인정보처리방침 URL |
| `tos_uri` | 서비스 이용약관 URL |
| `jwks_uri` | 클라이언트 JWK Set URL |

#### 6.3 클라이언트 유형

| 유형 | 설명 | 인증 방법 |
|-----|------|----------|
| Confidential | 서버 사이드 앱 (Secret 안전 보관 가능) | `client_secret_basic`, `private_key_jwt` 등 |
| Public | SPA, 모바일, 네이티브 앱 (Secret 보관 불가) | `none` (PKCE 필수) |

#### 6.4 Pushed Authorization Requests (선택)

- `POST /oauth2/par` — Authorization Request를 사전 등록하고 `request_uri`를 받아 사용
- 요청 파라미터 변조 방지 및 URL 길이 제한 회피
- 표준: [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)

---

### 7. 인가 (Authorization)

#### 7.1 RBAC (Role-Based Access Control)

| 기능 | 설명 |
|-----|------|
| Realm Role | Realm 전체 범위의 역할 (예: `admin`, `user`) |
| Client Role | 특정 클라이언트 범위의 역할 (예: `order-service:manager`) |
| Composite Role | 다른 역할을 집계하는 복합 역할 |
| Group | 사용자 그룹; 그룹에 역할 할당 시 구성원이 상속 |
| Role-to-Scope 매핑 | 역할을 OAuth 스코프에 매핑하여 API 레벨 인가 |
| 토큰 내 역할 | ID Token / Access Token에 `realm_access.roles`, `resource_access.{client}.roles` 포함 |

#### 7.2 동의 (Consent) 관리

| 기능 | 설명 |
|-----|------|
| 동의 화면 | Authorization 요청 시 요청된 스코프/권한을 사용자에게 표시 |
| 세분화된 동의 | 개별 스코프 승인/거부 가능 |
| 동의 저장 | 동일 클라이언트+스코프에 대해 동의 기억 (재요청 생략) |
| 동의 철회 | 사용자가 이전 동의를 철회 가능 |
| 동의 API | `GET /api/consents`, `DELETE /api/consents/{id}` |
| 1st Party 클라이언트 | 신뢰할 수 있는 자사 클라이언트는 동의 생략 (관리자 설정) |

---

### 8. Federation / 소셜 로그인

#### 8.1 외부 IdP 연동 (Identity Brokering)

| 기능 | 설명 |
|-----|------|
| OIDC Provider 연동 | Google, Azure AD, Okta 등 외부 OIDC Provider를 RP로 연결 |
| SAML IdP 연동 | 엔터프라이즈 SAML IdP 연결 |
| 소셜 로그인 | Google, Apple, GitHub, Kakao, Naver 등 사전 구성된 연동 |
| 첫 로그인 흐름 | 자동 계정 생성, 누락 속성 입력 요청, 기존 계정 연결 |
| 계정 연결 | 외부 IdP 계정을 기존 로컬 계정에 연결 (이메일 기반 자동 또는 수동) |
| IdP 클레임 매핑 | 외부 IdP의 클레임/속성을 로컬 사용자 속성 및 역할에 매핑 |

#### 8.2 디렉토리 연동 (선택)

| 기능 | 설명 |
|-----|------|
| LDAP/Active Directory | LDAP/AD에서 사용자 동기화 및 인증 위임 |
| On-Demand Provisioning | 첫 로그인 시 사용자 Import (Lazy Sync) |
| 주기적 동기화 | 스케줄된 전체/변경분 사용자 동기화 |

---

### 9. 보안

#### 9.1 Brute Force 방지

| 기능 | 설명 |
|-----|------|
| 실패 횟수 추적 | 사용자별, IP별 연속 로그인 실패 추적 |
| 점진적 지연 | 실패 시 지수적 대기 시간 증가 (1초, 2초, 4초, 8초...) |
| 임시 계정 잠금 | N회 실패 후 계정 잠금, M분 후 자동 해제 |
| IP 기반 제한 | IP별 시간 윈도우당 로그인 시도 제한 |
| CAPTCHA | N회 실패 후 CAPTCHA 요구 |
| 알림 | 계정 잠금 또는 의심스러운 로그인 시 이메일 알림 |

#### 9.2 Rate Limiting

| 대상 | 권장 제한 |
|-----|----------|
| 로그인 시도 | 사용자당 5~10회/분, IP당 20~50회/분 |
| Token Endpoint | 클라이언트당 100~500회/분 |
| 회원가입 | IP당 3~5회/시간 |
| 비밀번호 재설정 | 사용자당 3회/시간, IP당 10회/시간 |
| 응답 헤더 | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, HTTP 429 |

#### 9.3 PKCE (RFC 7636)

| 항목 | 설명 |
|-----|------|
| `code_challenge` | Authorization 요청에 포함. `BASE64URL(SHA256(code_verifier))` |
| `code_challenge_method` | `S256` (필수), `plain` (비권장) |
| `code_verifier` | Token 요청에 포함. 43~128자, 비예약 URI 문자 |
| 적용 범위 | Public 클라이언트 필수, 전체 클라이언트 권장 (RFC 9700) |

#### 9.4 감사 로깅 (Audit Log)

| 이벤트 카테고리 | 기록 대상 |
|---------------|----------|
| 인증 | 로그인 성공/실패, 로그아웃, MFA 시도/성공/실패 |
| 토큰 | 토큰 발급, 갱신, 무효화, Introspection |
| 사용자 관리 | 계정 생성, 수정, 삭제, 비밀번호 변경, 이메일 인증 |
| 클라이언트 관리 | 클라이언트 등록, 수정, 삭제 |
| 인가 | 동의 부여, 동의 철회, Authorization Code 발급 |
| 관리자 작업 | 관리자 로그인, 설정 변경, 역할 할당 |
| 보안 이벤트 | 계정 잠금, Brute Force 탐지, 의심 IP |

**감사 로그 레코드 필드:**

| 필드 | 설명 |
|-----|------|
| `timestamp` | ISO 8601 UTC |
| `event_type` | 이벤트 분류 식별자 |
| `user_id` | 대상 사용자 |
| `client_id` | 클라이언트 애플리케이션 |
| `ip_address` | 소스 IP |
| `user_agent` | 클라이언트 User Agent |
| `outcome` | `SUCCESS` / `FAILURE` |
| `details` | 추가 컨텍스트 (에러 코드, 변경 필드 등) |
| `session_id` | SSO 세션 식별자 |

#### 9.5 기타 보안 기능

| 기능 | 설명 | 표준 |
|-----|------|------|
| CORS | 브라우저 기반 클라이언트용 허용 Origin 설정 | |
| CSP | 로그인/동의 페이지 XSS 방지 헤더 | |
| CSRF | OAuth 흐름의 `state` 파라미터, SameSite 쿠키 | RFC 6749 §10.12 |
| TLS 필수 | 모든 엔드포인트 HTTPS 강제 | RFC 6749 §3.1 |
| Redirect URI 검증 | 정확한 문자열 매칭 (와일드카드 금지) | RFC 9700 |
| Issuer 검증 | ID Token의 `iss` 클레임 검증 | [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) |

---

### 10. 계정 복구

#### 10.1 비밀번호 재설정

| 요구사항 | 설명 |
|---------|------|
| 토큰 유효기간 | 15~60분 |
| 일회성 사용 | 사용 후 토큰 무효화 |
| 암호학적 토큰 | 최소 128비트 엔트로피의 랜덤 토큰 |
| Rate Limiting | 사용자별, IP별 요청 횟수 제한 |
| 사용자 열거 방지 | 이메일 존재 여부와 관계없이 동일한 응답 반환 |
| 세션 무효화 | 비밀번호 재설정 후 기존 세션 전체 무효화 |
| 알림 | 비밀번호 변경 성공 시 알림 이메일 발송 |

#### 10.2 계정 잠금/해제

| 기능 | 설명 |
|-----|------|
| 잠금 기준 | N회 실패 후 잠금 (설정 가능: 3~10회) |
| 잠금 기간 | 설정 가능 (1~30분, 점진적 증가) |
| 해제 방법 | 시간 경과 자동 해제, 이메일 인증 셀프 서비스, 관리자 수동 해제 |
| 잠금 알림 | 계정 잠금 시 이메일 알림 |

---

### 11. 관리 기능

#### 11.1 Admin Console

| 기능 | 설명 |
|-----|------|
| 사용자 관리 | CRUD, 검색, 필터, 비밀번호 초기화, 세션 종료 |
| 그룹 관리 | 그룹 생성/편집, 사용자 할당, 그룹 계층 |
| 역할 관리 | Realm/Client 역할 생성/편집, 사용자/그룹에 할당 |
| 클라이언트 관리 | OAuth 클라이언트 등록/편집/삭제 |
| IdP 관리 | 외부 IdP 설정, 클레임 매핑 관리 |
| 인증 흐름 설정 | MFA 정책, 필수 액션, 인증 흐름 커스터마이징 |
| 세션 관리 | 활성 세션 조회/종료 |
| 이벤트 뷰어 | 감사 로그 조회/검색 |
| 이메일 템플릿 | 인증, 비밀번호 재설정 등 이메일 템플릿 커스터마이징 |
| 테마/브랜딩 | 로그인, 동의 페이지 외관 커스터마이징 |

#### 11.2 Admin API

| 엔드포인트 | 설명 |
|-----------|------|
| `/admin/realms` | Realm CRUD |
| `/admin/realms/{realm}/users` | 사용자 관리 |
| `/admin/realms/{realm}/groups` | 그룹 관리 |
| `/admin/realms/{realm}/roles` | 역할 관리 |
| `/admin/realms/{realm}/clients` | 클라이언트 관리 |
| `/admin/realms/{realm}/identity-provider` | IdP 설정 |
| `/admin/realms/{realm}/authentication` | 인증 흐름 설정 |
| `/admin/realms/{realm}/events` | 이벤트 로그 |
| `/admin/realms/{realm}/attack-detection` | Brute Force 상태 관리 |

#### 11.3 모니터링

| 기능 | 설명 |
|-----|------|
| Health Check | `/actuator/health` — Liveness/Readiness Probe |
| Metrics | `/actuator/prometheus` — JVM, 요청, 토큰, 세션 메트릭 |
| 주요 지표 | 활성 세션 수, 토큰 발급률, 로그인 성공/실패율, MFA 채택률 |
| 분산 추적 | OpenTelemetry / Micrometer Tracing |

---

### 12. 전체 엔드포인트 맵

```
OAuth 2.0 / OIDC 프로토콜:
  GET  /.well-known/openid-configuration
  GET  /oauth2/jwks
  GET  /oauth2/authorize
  POST /oauth2/token
  POST /oauth2/revoke
  POST /oauth2/introspect
  POST /oauth2/register
  GET  /oauth2/register/{client_id}
  PUT  /oauth2/register/{client_id}
  DELETE /oauth2/register/{client_id}
  GET  /userinfo
  GET  /oauth2/logout

사용자 인증/계정 (UI):
  GET  /oauth2/login                  # 로그인 페이지
  GET  /oauth2/register               # 회원가입 페이지
  POST /oauth2/register               # 회원가입 처리
  GET  /oauth2/forgot-password         # 비밀번호 찾기 페이지
  POST /oauth2/forgot-password         # 비밀번호 찾기 처리
  GET  /oauth2/reset-password?token=   # 비밀번호 초기화 페이지
  POST /oauth2/reset-password          # 비밀번호 초기화 처리
  GET  /oauth2/verify-email?token=     # 이메일 인증 처리 + 결과 페이지

사용자 인증/계정 (API):
  POST /api/auth/register
  GET  /api/auth/verify-email
  POST /api/auth/forgot-password
  POST /api/auth/reset-password
  POST /api/auth/change-password

MFA:
  POST /api/mfa/totp/setup
  POST /api/mfa/totp/verify
  POST /api/mfa/totp/validate
  POST /api/mfa/webauthn/register/options
  POST /api/mfa/webauthn/register/verify
  POST /api/mfa/webauthn/authenticate/options
  POST /api/mfa/webauthn/authenticate/verify
  POST /api/mfa/recovery-codes
  POST /api/mfa/recovery-codes/verify
  GET  /api/mfa/methods
  DELETE /api/mfa/methods/{id}

사용자 프로필/동의/세션:
  GET    /api/users/me
  PUT    /api/users/me
  DELETE /api/users/me
  GET    /api/consents
  DELETE /api/consents/{id}
  GET    /api/sessions
  DELETE /api/sessions/{id}

관리자 (UI):
  GET  /admin/console                  # 관리 콘솔 (대시보드, 사용자, 클라이언트, 세션, 이벤트, IdP)
  GET  /admin/settings                 # 프레임워크 설정

관리자 (API):
  GET  /admin/api/stats                # 대시보드 통계
  GET  /admin/api/users                # 사용자 목록
  POST /admin/api/users/{id}/lock      # 사용자 잠금
  POST /admin/api/users/{id}/unlock    # 사용자 해제
  POST /admin/api/users/{id}/reset-password  # 비밀번호 초기화
  POST /admin/api/users/{id}/revoke-sessions # 세션 만료
  GET  /admin/api/clients              # 클라이언트 목록
  POST /admin/api/clients              # 클라이언트 생성
  PUT  /admin/api/clients/{id}         # 클라이언트 수정
  DELETE /admin/api/clients/{id}       # 클라이언트 삭제
  GET  /admin/api/sessions             # 활성 세션 목록
  POST /admin/api/sessions/{id}/revoke # 세션 폐기
  GET  /admin/api/events               # 감사 로그
  GET  /admin/api/identity-providers   # IdP 목록
  POST /admin/api/identity-providers   # IdP 생성
  PUT  /admin/api/identity-providers/{id}    # IdP 수정
  DELETE /admin/api/identity-providers/{id}  # IdP 삭제

모니터링:
  GET /actuator/health
  GET /actuator/prometheus
  GET /actuator/info
```

---

### 13. 참조 표준 목록

#### OAuth 2.0 / OIDC

| 표준 | 제목 |
|-----|------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 Authorization Framework |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer Token Usage |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token Revocation |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key (JWK) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | JWT Profile for Client Authentication |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration |
| [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592) | Dynamic Client Registration Management |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata |
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Grant |
| [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) | Token Exchange |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT Access Token Profile |
| [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) | Pushed Authorization Requests (PAR) |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | Authorization Server Issuer Identification |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP |
| [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) | OAuth 2.0 Security BCP |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | OpenID Connect Core |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | OpenID Connect Discovery |
| [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | RP-Initiated Logout |
| [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Back-Channel Logout |

#### JOSE (JSON Object Signing and Encryption)

| 표준 | 제목 |
|-----|------|
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature (JWS) |
| [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) | JSON Web Encryption (JWE) |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms (JWA) |

#### MFA / 인증

| 표준 | 제목 |
|-----|------|
| [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) | TOTP |
| [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) | HOTP |
| [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) | Web Authentication API |
| NIST SP 800-63B | Digital Identity Guidelines: Authentication |

#### 사용자 프로비저닝

| 표준 | 제목 |
|-----|------|
| [RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643) | SCIM Core Schema |
| [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) | SCIM Protocol |

---

## 구현 로드맵

전체 구현을 7단계(Phase)로 나눕니다. 각 Phase는 이전 Phase의 결과물 위에 쌓이는 구조이며, Phase 내부 스텝은 순서대로 진행합니다.

### Phase 1 — 핵심 인프라 및 데이터 모델 ✅

> OAuth 2.0/OIDC의 모든 기능이 의존하는 기반 계층. 이 단계가 완료되어야 이후 모든 Phase가 진행 가능합니다.

#### 1-1. 도메인 엔티티 및 JPA 설정

- [x] **사용자(User) 엔티티** — `id`, `username`, `email`, `password_hash`, `email_verified`, `enabled`, `created_at`, `updated_at`
- [x] **역할(Role) 엔티티** — `id`, `name`, `description`, `type`(REALM/CLIENT)
- [x] **사용자-역할 매핑 테이블** — `user_id`, `role_id`
- [x] **그룹(Group) 엔티티** — `id`, `name`, `parent_id` (계층 구조)
- [x] **그룹-역할 매핑 테이블**, **사용자-그룹 매핑 테이블**
- [x] JPA Repository 구성
- [x] H2 file 모드 전환 — `jdbc:h2:file:./data/licadb;DB_CLOSE_ON_EXIT=FALSE`
- [x] `ddl-auto`를 `update`로 변경 (엔티티 변경 시 스키마 자동 반영, 운영 안정화 후 `validate` + Flyway 전환 검토)

#### 1-2. 비밀번호 해싱 및 인증 기반

- [x] `PasswordEncoder` 빈 (bcrypt, work factor 12)
- [x] `UserDetailsService` 구현 — DB에서 사용자 조회, 역할 로딩
- [x] `AuthenticationManager` / `AuthenticationProvider` 구성

#### 1-3. RSA 키 쌍 관리 (JWK)

- [x] RSA 2048+ 키 쌍 생성/로드 로직 (`KeyPair`, `RSAKey`)
- [x] JWK Set 구성 — `kid` 포함, 키 로테이션 고려한 설계
- [x] `GET /oauth2/jwks` 엔드포인트 (공개키 노출)
- [x] JWT 서명/검증 유틸리티 — 기존 HMAC 기반 `JwtTokenProvider`를 RSA 기반으로 전환

#### 1-4. 설정 체계 정비

- [x] `application.properties` → `application.yml` 전환 (프로파일 분리)
- [x] SSO 전용 설정 프로퍼티 클래스 (`SsoProperties`) — issuer URL, 토큰 유효기간, 키 경로 등
- [x] 프로파일별 설정: `local` (H2 인메모리, 개발/테스트), `prod` (H2 file, 운영)

**완료 기준:** ~~애플리케이션 기동 시 H2 file DB에 스키마 생성, 재시작 후 데이터 유지 확인, `/oauth2/jwks`에서 RSA 공개키 반환, 사용자 생성/인증 테스트 통과.~~ ✅ 완료 (2026-02-08)

---

### Phase 2 — OAuth 2.0 Core ✅

> Authorization Server의 핵심. 모든 OAuth 2.0 Grant 흐름과 토큰 발급/관리를 구현합니다.

#### 2-1. 클라이언트(OAuth Client) 엔티티 및 관리

- [x] **OAuth Client 엔티티** — `client_id`, `client_secret_hash`, `client_name`, `redirect_uris`, `grant_types`, `response_types`, `scopes`, `token_endpoint_auth_method`, `client_type`(CONFIDENTIAL/PUBLIC), `logo_uri`, `policy_uri`, `tos_uri`, `jwks_uri`, `enabled`, `created_at`
- [x] Client Repository, Client 조회/검증 서비스
- [x] 클라이언트 인증 로직 — `client_secret_basic`, `client_secret_post`, `none`(Public)

#### 2-2. Authorization Code + PKCE 흐름

- [x] **Authorization Code 엔티티** — `code`, `client_id`, `user_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method`, `expires_at`, `used`
- [x] `GET /oauth2/authorize` — 인증 확인 → 로그인 페이지 리다이렉트 → 동의 화면 → Authorization Code 발급 → redirect_uri로 리다이렉트
- [x] PKCE 검증 (`S256`) — `code_challenge` 저장, `code_verifier` 검증
- [x] `state` 파라미터 전달 및 반환
- [ ] `response_mode` 지원: `query`, `fragment`, `form_post`
- [x] 에러 응답 처리 (RFC 6749 §4.1.2.1) — `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`

#### 2-3. Token Endpoint

- [x] `POST /oauth2/token` — Grant Type별 분기 처리
- [x] **Authorization Code 교환** — code 검증, PKCE 검증, 사용 후 무효화, Access Token + Refresh Token + ID Token 발급
- [x] **Client Credentials** — 클라이언트 인증 후 Access Token 발급 (사용자 컨텍스트 없음)
- [x] **Refresh Token** — Refresh Token 검증, 새 Access Token + 새 Refresh Token 발급 (Rotation)
- [x] Access Token 형식: JWT (RFC 9068 클레임 포함)
- [x] Refresh Token 형식: Opaque + DB 저장

#### 2-4. Refresh Token 엔티티 및 Rotation

- [x] **Refresh Token 엔티티** — `token_hash`, `user_id`, `client_id`, `scope`, `expires_at`, `family_id`, `revoked`, `replaced_by`
- [x] Rotation 구현 — 사용 시 새 토큰 발급 + 이전 토큰 무효화
- [x] Replay Detection — 이미 사용된 토큰으로 요청 시 전체 `family_id` 무효화

#### 2-5. Token Revocation & Introspection

- [x] `POST /oauth2/revoke` (RFC 7009) — Access Token / Refresh Token 무효화
- [x] `POST /oauth2/introspect` (RFC 7662) — 토큰 활성 상태 조회, 인가된 클라이언트만 접근 가능
- [x] Access Token 무효화를 위한 토큰 블랙리스트 (Redis 또는 DB)

#### 2-6. Authorization Server Metadata

- [x] `GET /.well-known/oauth-authorization-server` (RFC 8414) — 서버 메타데이터 자동 생성/반환

**완료 기준:** ~~Authorization Code + PKCE 전체 흐름 동작, Client Credentials 동작, Refresh Token Rotation 동작, Revocation/Introspection 동작. Postman 또는 테스트 코드로 전체 흐름 검증.~~ ✅ 완료 (2026-02-17)

---

### Phase 3 — OpenID Connect ✅

> OAuth 2.0 위에 OIDC 레이어를 얹어 ID Token 발급, UserInfo, Discovery를 추가합니다.

#### 3-1. ID Token 발급

- [x] ID Token 생성 로직 — 필수 클레임(`iss`, `sub`, `aud`, `exp`, `iat`) + 조건부 클레임(`auth_time`, `nonce`, `at_hash`, `acr`, `amr`)
- [x] `at_hash` 계산 — Access Token의 SHA-256 해시 좌측 절반, Base64URL 인코딩
- [x] `nonce` 처리 — Authorization Request에서 전달받아 ID Token에 포함
- [x] Authorization Code 흐름에서 Token Response에 `id_token` 포함

#### 3-2. OIDC Scope 및 클레임 매핑

- [x] `openid` 스코프 감지 → OIDC 흐름으로 전환 (ID Token 발급)
- [x] 스코프별 클레임 매핑 — `profile`, `email`, `address`, `phone` → 해당 사용자 속성 반환
- [x] User 엔티티 확장 — OIDC 표준 클레임 필드 추가 (`given_name`, `family_name`, `nickname`, `picture`, `phone_number` 등)

#### 3-3. UserInfo Endpoint

- [x] `GET /userinfo` — Access Token 기반 사용자 정보 반환
- [x] Bearer Token 인증 (Authorization 헤더)
- [x] 부여된 스코프에 따라 반환 클레임 필터링

#### 3-4. OIDC Discovery

- [x] `GET /.well-known/openid-configuration` — 전체 메타데이터 자동 생성
- [x] 포함 항목: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `scopes_supported`, `response_types_supported`, `grant_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`, `revocation_endpoint`, `introspection_endpoint`

#### 3-5. Dynamic Client Registration (선택)

- [x] `POST /oauth2/register` (RFC 7591) — 클라이언트 자동 등록
- [x] `GET/PUT/DELETE /oauth2/register/{client_id}` (RFC 7592) — 등록 관리
- [x] Registration Access Token 발급 및 검증

**완료 기준:** ~~`openid` 스코프 포함 시 ID Token 발급, `/userinfo`에서 스코프 기반 클레임 반환, `/.well-known/openid-configuration` 정상 응답. 외부 OIDC 클라이언트 라이브러리(예: `spring-security-oauth2-client`)로 연동 테스트 통과.~~ ✅ 완료 (2026-02-17)

---

### Phase 4 — 세션 관리 및 로그인 UI ✅

> SSO의 핵심인 세션 관리와 사용자 대면 UI를 구현합니다.

#### 4-1. SSO 세션 관리

- [x] **SSO Session 엔티티** — `session_id`, `user_id`, `ip_address`, `user_agent`, `created_at`, `last_active_at`, `expires_at`
- [x] 세션 쿠키 설정 — HttpOnly, Secure, SameSite=Lax, Path=/
- [x] 세션 저장소 — H2 DB (로컬 개발)
- [x] Idle Timeout (기본 30분), Absolute Timeout (기본 8시간)
- [x] Session Fixation 방지 — 인증 성공 시 Session ID 재생성
- [x] 동시 세션 제한 — 사용자당 최대 세션 수 설정, 초과 시 가장 오래된 세션 종료

#### 4-2. SSO 세션과 OAuth 흐름 연동

- [x] `/oauth2/authorize` 요청 시 SSO 세션 확인 → 유효하면 로그인 생략 (SSO 동작)
- [x] SSO 세션에 참여 클라이언트 목록 기록 (SLO 시 사용)
- [x] `prompt` 파라미터 처리 — `none` (세션 없으면 에러), `login` (강제 재인증), `consent` (동의 강제)
- [x] `max_age` 파라미터 처리 — 마지막 인증 시간 확인, 초과 시 재인증

#### 4-3. 로그인/동의 UI

- [x] 로그인 페이지 — username/password 입력, 에러 메시지, "비밀번호 찾기" 링크
- [x] 동의 화면 — 클라이언트 정보(이름, 로고), 요청 스코프 목록, 승인/거부 버튼
- [x] 로그아웃 확인 페이지 — 로그아웃 대상 클라이언트 표시
- [x] Thymeleaf 템플릿 기반, 향후 테마/브랜딩 커스터마이징 고려

#### 4-4. Single Logout (SLO)

- [x] `GET /oauth2/logout` — RP-Initiated Logout
  - `id_token_hint` → 사용자 식별, `post_logout_redirect_uri` → 로그아웃 후 리다이렉트
  - SSO 세션 종료, 참여 클라이언트에 로그아웃 전파
- [x] **Back-Channel Logout** — 각 RP의 `backchannel_logout_uri`로 Logout Token(JWT) POST 전송
  - Logout Token 클레임: `iss`, `sub`, `aud`, `iat`, `jti`, `events`, `sid`
- [ ] **Front-Channel Logout** (선택) — hidden iframe으로 각 RP의 `frontchannel_logout_uri` 호출
- [x] OIDC Discovery에 `end_session_endpoint`, `backchannel_logout_supported`, `backchannel_logout_session_supported` 추가

**완료 기준:** ~~여러 클라이언트에서 동일 SSO 세션으로 로그인, 한 곳에서 로그아웃 시 전체 세션 종료. `prompt=none` SSO, `prompt=login` 재인증, Back-Channel Logout 동작 확인.~~ ✅ 완료 (2026-02-19)

---

### Phase 5 — 사용자 관리 및 MFA ✅

> 사용자 셀프 서비스 기능과 다중 인증을 추가합니다.

#### 5-1. 회원가입 및 이메일 인증

- [x] `POST /api/auth/register` — 사용자 등록 (username, email, password)
- [x] 비밀번호 정책 검증 — 최소 길이, 숫자/특수문자 포함 필수
- [x] 이메일 인증 토큰 발급 및 발송 (Mail 모듈 비활성 시 로그 출력)
- [x] `GET /api/auth/verify-email?token=...` — 이메일 인증 완료
- [x] 사용자 열거 방지 — 등록 시 이메일 중복 여부를 응답으로 노출하지 않음

#### 5-2. 비밀번호 재설정

- [x] `POST /api/auth/forgot-password` — 재설정 토큰 발급, 이메일 발송
- [x] `POST /api/auth/reset-password` — 토큰 검증, 새 비밀번호 설정
- [x] 토큰 유효기간 (30분), 일회성 사용, 256비트 랜덤 토큰
- [x] 재설정 완료 시 전체 기존 세션 무효화
- [x] 변경 성공 알림 이메일 발송

#### 5-3. 프로필 관리

- [x] `GET /api/users/me` — 내 프로필 조회
- [x] `PUT /api/users/me` — 프로필 수정 (이름, 전화번호 등)
- [x] `POST /api/auth/change-password` — 비밀번호 변경 (현재 비밀번호 확인 필수)
- [x] `DELETE /api/users/me` — 계정 비활성화/삭제

#### 5-4. TOTP 기반 MFA

- [x] `POST /api/mfa/totp/setup` — Secret 생성, QR 코드 URI 반환 (`otpauth://totp/...`)
- [x] `POST /api/mfa/totp/verify` — 초기 등록 확인 (사용자가 코드 입력)
- [x] `POST /api/mfa/totp/validate` — 로그인 시 TOTP 검증
- [x] TOTP 크레덴셜 엔티티 — `user_id`, `secret`, `algorithm`, `digits`, `period`, `verified`, `created_at`
- [x] 허용 오차: ±1 스텝 (이전/현재/다음 30초 윈도우)

#### 5-5. 복구 코드

- [x] `POST /api/mfa/recovery-codes` — 10개 일회용 복구 코드 생성 (해싱 저장)
- [x] `POST /api/mfa/recovery-codes/verify` — 복구 코드 검증 (사용 후 무효화)
- [x] MFA 등록 시 복구 코드 필수 생성 안내

#### 5-6. MFA 정책 및 로그인 흐름 통합

- [x] 로그인 흐름 수정: 1차 인증(비밀번호) → MFA 등록 여부 확인 → 2차 인증(TOTP/복구코드) → SSO 세션 발급
- [x] MFA 중간 상태 관리 — 1차 인증 성공 후 MFA 대기 상태를 HttpSession에 저장
- [ ] MFA 정책 설정: 필수 / 선택 / 조건부 (글로벌 설정)
- [x] `GET /api/mfa/methods` — 등록된 MFA 방법 조회
- [x] `DELETE /api/mfa/methods/{id}` — MFA 방법 삭제
- [ ] `amr` 클레임에 사용된 인증 방법 기록 (`pwd`, `otp`, `mfa`)

#### 5-7. WebAuthn/FIDO2 (선택)

- [ ] WebAuthn Registration — `PublicKeyCredentialCreationOptions` 생성 및 검증
- [ ] WebAuthn Authentication — `PublicKeyCredentialRequestOptions` 생성 및 검증
- [ ] WebAuthn Credential 엔티티 — `user_id`, `credential_id`, `public_key`, `sign_count`, `transports`, `created_at`
- [ ] Passkey 지원 — Resident Key (`requireResidentKey: true`)

**완료 기준:** ~~회원가입 → 이메일 인증 → 로그인 → MFA 등록 → MFA 포함 로그인 전체 흐름 동작. 비밀번호 재설정 이메일 발송 및 재설정 완료, 복구 코드로 MFA 우회 가능.~~ ✅ 완료 (2026-02-19)

---

### Phase 6 — 보안 강화 및 관리 기능 ✅

> 운영 환경에 필요한 보안 기능과 관리자 콘솔을 구현합니다.

#### 6-1. Brute Force 방지

- [x] 로그인 실패 추적 — 사용자별 실패 횟수 및 마지막 실패 시간 기록
- [x] 점진적 지연 — 연속 실패 시 지수적 대기 (1초 → 2초 → 4초 → ...)
- [x] 임시 계정 잠금 — 5회 실패 후 잠금, 15분 후 자동 해제
- [x] IP 기반 Rate Limiting — 시간 윈도우당 IP별 최대 시도 횟수
- [ ] 잠금 알림 이메일 발송

#### 6-2. Rate Limiting

- [x] Token Endpoint — IP당 60 req/min
- [x] Registration — IP당 10 req/hour
- [x] Password Reset — IP당 5 req/hour
- [x] Rate Limit 응답 헤더: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- [x] HTTP 429 Too Many Requests 응답
- [x] 구현 방식: In-Memory Sliding Window (Redis 미사용 시)

#### 6-3. 감사 로깅 (Audit Log)

- [x] **Audit Log 엔티티** — `timestamp`, `event_type`, `user_id`, `client_id`, `ip_address`, `user_agent`, `outcome`, `details`, `session_id`
- [x] 이벤트 기반 로깅 (서비스 호출)
- [x] 인증 이벤트: 로그인 성공/실패, MFA 대기
- [ ] 토큰 이벤트: 발급, 갱신, 무효화
- [ ] 사용자 이벤트: 계정 생성, 수정, 삭제, 비밀번호 변경
- [x] 보안 이벤트: 계정 잠금 (Brute Force 로깅)

#### 6-4. 동의(Consent) 관리

- [x] **User Consent 엔티티** — `user_id`, `client_id`, `scopes`, `granted_at`, `expires_at`
- [x] Authorization 흐름에서 동의 확인 — 기존 동의가 있고 스코프가 동일하면 동의 화면 생략
- [x] 1st Party 클라이언트 플래그 — 동의 화면 자동 생략
- [x] `GET /api/consents` — 사용자의 활성 동의 목록
- [x] `DELETE /api/consents/{id}` — 동의 철회
- [x] `prompt=consent` 지원 — 기존 동의 무시하고 동의 화면 재표시

#### 6-5. Admin Console 확장

- [x] 기존 Admin UI를 SSO 관리 기능으로 확장 (REST API 기반)
- [x] 사용자 관리 — 목록, 상세, 비밀번호 초기화, 계정 잠금/해제, 세션 종료
- [x] 클라이언트 관리 — OAuth 클라이언트 CRUD (redirect_uri, grant_types, scopes 설정)
- [x] 역할 관리 — Realm Role CRUD
- [x] 이벤트 뷰어 — 감사 로그 조회/검색/필터링
- [x] 세션 뷰어 — 활성 SSO 세션 조회/강제 종료

#### 6-6. Admin REST API

- [x] `/admin/api/users` — 사용자 목록, 상세, 비밀번호 초기화, 잠금/해제, 세션 종료
- [x] `/admin/api/clients` — 클라이언트 CRUD
- [x] `/admin/api/roles` — 역할 CRUD
- [x] `/admin/api/groups` — 그룹 목록
- [x] `/admin/api/events` — 감사 로그 조회
- [x] `/admin/api/sessions` — 세션 관리
- [x] `/admin/api/attack-detection/{username}` — Brute Force 상태 조회/해제
- [x] Admin API 인증 — 기존 Admin 세션 기반 인증 (ROLE_ADMIN)

**완료 기준:** ~~로그인 5회 실패 시 계정 잠금 확인, Rate Limit 초과 시 429 응답, 감사 로그에 모든 인증/보안 이벤트 기록, Admin Console에서 사용자/클라이언트/역할 관리 가능.~~ ✅ 완료 (2026-02-19)

---

### Phase 7 — Federation, 확장 기능, 운영 준비 ✅

> 외부 IdP 연동, 고급 프로토콜, 운영 환경 배포 준비를 완료합니다.

#### 7-1. 소셜 로그인 / 외부 OIDC Provider 연동

- [x] **Identity Provider 엔티티** — `alias`, `provider_type`(OIDC/SOCIAL), `client_id`, `client_secret`, `authorization_url`, `token_url`, `userinfo_url`, `jwks_url`, `scopes`, `claim_mappings`, `enabled`
- [x] OIDC RP 구현 — 외부 Provider에 Authorization Code 흐름 실행
- [x] 소셜 로그인 사전 구성 — Google, GitHub, Kakao, Naver
- [x] 첫 로그인 흐름 — 자동 계정 생성, 이메일 기반 기존 계정 자동 연결
- [x] **Federated Identity 엔티티** — `user_id`, `idp_alias`, `external_user_id`, `external_username`, `linked_at`
- [x] IdP 클레임 매핑 — 외부 클레임을 로컬 사용자 속성/역할에 매핑 (provider별 추출 로직)
- [x] 로그인 페이지에 소셜 로그인 버튼 추가
- [x] Admin API — IdP CRUD (`/admin/api/identity-providers`)

#### 7-2. 이메일 템플릿

- [x] 이메일 인증, 비밀번호 재설정, 계정 잠금 알림, 비밀번호 변경 알림 등 템플릿
- [x] Thymeleaf 기반 HTML 이메일 템플릿
- [x] 다국어 지원 (한국어, 영어) — Spring MessageSource 기반
- [ ] Admin Console에서 템플릿 커스터마이징 (선택)

#### 7-3. 모니터링 및 Observability

- [x] Actuator 모듈 활성화 — Health Check, Info, Metrics, Prometheus
- [x] Prometheus 메트릭 노출 — `/actuator/prometheus`
- [x] 커스텀 메트릭: 활성 세션 수, 토큰 발급률, 로그인 성공/실패율, MFA 채택률
- [x] 구조화 로깅 (JSON 포맷) — Logstash Encoder, ELK/Loki 호환
- [x] 요청 Correlation ID — MDC 기반 추적 ID + `X-Correlation-Id` 응답 헤더

#### 7-4. CORS 및 보안 헤더

- [x] CORS 설정 — `CorsConfigurationSource` Bean, `X-Correlation-Id` 노출
- [x] 보안 헤더 — CSP, X-Content-Type-Options, HSTS, X-Frame-Options
- [ ] Redirect URI 엄격 검증 — 정확한 문자열 매칭, 와일드카드 금지 (기존 Phase 2에서 구현 완료)

#### 7-5. 운영 환경 배포 준비

- [x] Docker 이미지 빌드 (Dockerfile, `.dockerignore`)
- [x] `docker-compose.yml` — 앱 단일 컨테이너 (H2 file 볼륨 마운트)
- [x] 환경변수 기반 설정 주입 — `SSO_ISSUER`, `SSO_KEY_STORE_PATH`, `SPRING_PROFILES_ACTIVE`
- [x] `application-prod.yml` — H2 file 모드, 로그 레벨 조정
- [x] Graceful Shutdown 설정 (30s timeout)
- [x] Actuator health endpoint 공개, 나머지 ADMIN 권한 제한

#### 7-6. 고급 기능 (선택)

아래 기능은 핵심 SSO 운영 이후 필요 시 구현합니다:

- [ ] SAML 2.0 IdP — SAML SSO/SLO, 메타데이터 엔드포인트
- [ ] SCIM 2.0 — 사용자/그룹 프로비저닝 API
- [ ] Device Authorization Grant (RFC 8628) — 스마트 TV, CLI 등 입력 제한 디바이스용
- [ ] Pushed Authorization Requests (RFC 9126)
- [ ] DPoP (RFC 9449) — Sender-Constrained Token
- [ ] LDAP/Active Directory 연동
- [ ] Multi-Tenancy (Realm) — 테넌트별 격리된 사용자/클라이언트/설정
- [ ] 테마/브랜딩 시스템 — 클라이언트별 로그인 페이지 커스터마이징

**완료 기준:** 소셜 로그인(Google 등)으로 회원가입/로그인 동작, Docker 환경에서 전체 스택 기동, Prometheus 메트릭 수집, 구조화 로그 출력. 외부 서비스에서 OIDC 클라이언트로 SSO 연동 완료.

---

### 구현 순서 요약

```
Phase 1: 핵심 인프라 ──────────────────────────────────── 기반
  └─ 엔티티, JPA, H2 file, RSA 키, 비밀번호 해싱

Phase 2: OAuth 2.0 Core ──────────────────────────────── 인가
  └─ Client 관리, AuthZ Code+PKCE, Token 발급/관리, Revocation, Introspection

Phase 3: OpenID Connect ──────────────────────────────── 인증
  └─ ID Token, UserInfo, OIDC Discovery, Scope/Claim 매핑

Phase 4: 세션 관리 + 로그인 UI ───────────────────────── SSO
  └─ SSO 세션, 로그인/동의 UI, prompt/max_age, Single Logout

Phase 5: 사용자 관리 + MFA ───────────────────────────── 사용자
  └─ 회원가입, 이메일 인증, 비밀번호 재설정, TOTP, 복구 코드

Phase 6: 보안 + 관리 기능 ────────────────────────────── 운영
  └─ Brute Force, Rate Limiting, Audit Log, Consent, Admin Console

Phase 7: Federation + 배포 ───────────────────────────── 확장
  └─ 소셜 로그인, 이메일 템플릿, 모니터링, Docker, 고급 기능
```

---

### AWS 단일 인스턴스 TPS 예측

> 단일 인스턴스 + H2 file 모드 기준. SSO 서비스의 병목은 **bcrypt 비밀번호 해싱**(CPU-bound)이므로 vCPU 수가 처리량을 결정합니다.

#### 요청 유형별 단가

| 요청 유형 | 주요 연산 | 코어당 처리 시간 |
|----------|----------|----------------|
| **로그인** (비밀번호 인증) | bcrypt 검증 (cost 10) | ~100ms/건 |
| **토큰 발급** (Code→Token) | RSA 서명 + DB 쓰기 | ~5ms/건 |
| **토큰 갱신** (Refresh) | RSA 서명 + DB 읽기/쓰기 | ~5ms/건 |
| **토큰 검증** (Introspection) | RSA 검증 또는 DB 조회 | ~1ms/건 |
| **SSO 세션 확인** (authorize) | 쿠키→DB 조회 | ~1ms/건 |
| **UserInfo** | Bearer 검증 + DB 조회 | ~2ms/건 |
| **JWKS / Discovery** | 정적 응답 (캐시) | ~0.1ms/건 |

> bcrypt cost factor 기준: **cost 10 ≈ 100ms**, cost 12 ≈ 400ms. cost 10이 보안과 성능의 균형점으로 적합합니다.

#### 인스턴스별 예측 TPS

**로그인 TPS** (최대 병목인 bcrypt 기준):

| 인스턴스 | vCPU | 메모리 | 로그인 TPS | 토큰 발급/갱신 TPS | 토큰 검증/세션 TPS | 월 비용 (서울) |
|---------|------|-------|-----------|------------------|-----------------|-------------|
| **t3.micro** | 2 | 1 GB | ~15 | ~200 | ~1,000 | ~$10 |
| **t3.small** | 2 | 2 GB | ~18 | ~300 | ~1,500 | ~$20 |
| **t3.medium** | 2 | 4 GB | ~18 | ~350 | ~1,800 | ~$40 |
| **t3.large** | 2 | 8 GB | ~18 | ~350 | ~1,800 | ~$75 |
| **t3.xlarge** | 4 | 16 GB | ~35 | ~700 | ~3,500 | ~$150 |
| **c6i.large** | 2 | 4 GB | ~20 | ~400 | ~2,000 | ~$80 |
| **c6i.xlarge** | 4 | 8 GB | ~40 | ~800 | ~4,000 | ~$160 |
| **c7g.medium** (ARM) | 1 | 2 GB | ~12 | ~200 | ~1,000 | ~$30 |
| **c7g.large** (ARM) | 2 | 4 GB | ~22 | ~450 | ~2,200 | ~$60 |

> **t3 시리즈 주의:** Burstable 인스턴스로 CPU 크레딧 소진 시 baseline(20~40%)으로 성능 제한. 지속적 부하에는 c6i/c7g 계열 권장.

#### 실제 운영 트래픽 패턴

SSO 서비스는 대부분의 요청이 토큰/세션 기반(bcrypt 미사용)이므로, 실제 혼합 TPS는 로그인 TPS보다 훨씬 높습니다:

```
실제 트래픽 비율 (일반적 SSO):
  로그인 (bcrypt)      :  5~15%  ← 하루 1~2회/사용자
  SSO 세션 확인         : 30~40%  ← 새 앱 접근 시 (bcrypt 없음)
  토큰 갱신 (Refresh)   : 20~30%  ← Access Token 만료 시
  토큰 검증/UserInfo    : 20~30%  ← Resource Server 요청 시
  기타 (JWKS, Discovery): ~5%    ← 캐시 가능
```

| 인스턴스 | 혼합 TPS (예상) | 동시 사용자 수 (추정) |
|---------|---------------|--------------------|
| **t3.small** | ~100~150 | ~500~1,000명 |
| **t3.medium** | ~120~180 | ~600~1,200명 |
| **c6i.large** | ~150~250 | ~800~1,500명 |
| **c6i.xlarge** | ~300~500 | ~1,500~3,000명 |

> **동시 사용자 수 추정 근거:** 사용자 1명이 분당 평균 0.1~0.2 요청 발생 기준.

#### 인스턴스 선택 가이드

| 규모 | 총 사용자 | 권장 인스턴스 | 근거 |
|-----|----------|-------------|------|
| 소규모 | ~1,000명 | **t3.small** | 충분한 성능, 최저 비용 |
| 중규모 | ~5,000명 | **t3.medium** 또는 **c7g.large** | JVM 힙 여유, 안정적 |
| 대규모 | ~10,000명+ | **c6i.xlarge** | 전용 CPU, 높은 처리량 |

> H2 file 모드의 DB I/O는 EBS gp3 기본 성능(3,000 IOPS)으로 충분합니다. SSO 서비스 특성상 DB 부하는 낮으며, bcrypt CPU가 지배적 병목입니다.

---

## 기술 스택

- **Java** 21
- **Spring Boot** 3.5.0
- **Spring Web** - REST API
- **Spring JDBC** - JDBC 데이터 액세스 (선택적 모듈)
- **Spring Data JPA** - ORM 데이터 액세스 (선택적 모듈)
- **QueryDSL** - 타입 안전 쿼리 (선택적 모듈)
- **Spring Security** - 인증/인가 (JWT 기반)
- **H2 Database** - 임베디드 데이터베이스 (file 모드, 단일 인스턴스 운영)
- **JWT (jjwt)** - JSON Web Token 인증
- **Validation** - Bean Validation (기본 포함)
- **Lombok** - 보일러플레이트 코드 제거 (기본 포함)
- **MapStruct** - Entity/DTO 변환 코드 생성 (기본 포함)
- **Actuator** - 모니터링/헬스체크 (선택적 모듈)
- **OpenAPI (springdoc)** - Swagger API 문서 (선택적 모듈)
- **Flyway** - DB 마이그레이션 (선택적 모듈)
- **Mail** - 이메일 발송 (선택적 모듈)
- **AOP** - AspectJ 기반 관점 지향 프로그래밍 (선택적 모듈)
- **WebSocket** - 실시간 양방향 통신 (선택적 모듈)
- **OAuth2 Resource Server** - OAuth2 JWT 리소스 서버 (선택적 모듈)
- **Thymeleaf** - 서버 사이드 템플릿 엔진 (선택적 모듈)
- **GraphQL** - GraphQL API (선택적 모듈)
- **Config Reload** - 설정 파일 변경 자동 리로드 (선택적 모듈)
- **P6Spy** - SQL 로그 파라미터 바인딩 (선택적 모듈)
- **DevTools** - 개발 시 자동 재시작/LiveReload (선택적 모듈)
- **Redis** - 캐싱 및 세션 관리 (선택적 모듈)
- **Kafka** - 메시지 브로커 (선택적 모듈)
- **RabbitMQ** - 메시지 큐 (선택적 모듈)
- **Gradle** (Kotlin DSL) - 빌드 도구
- **JUnit 5** - 테스트

## 프로젝트 구조

```
src/
├── main/
│   ├── java/com/spring/lica/
│   │   ├── LicaApplication.java
│   │   ├── config/
│   │   │   ├── SecurityConfig.java
│   │   │   ├── JdbcConfig.java
│   │   │   ├── JpaConfig.java
│   │   │   ├── QueryDslConfig.java
│   │   │   ├── ActuatorConfig.java
│   │   │   ├── OpenApiConfig.java
│   │   │   ├── FlywayConfig.java
│   │   │   ├── MailConfig.java
│   │   │   ├── AopConfig.java
│   │   │   ├── WebSocketConfig.java
│   │   │   ├── OAuth2Config.java
│   │   │   ├── ThymeleafConfig.java
│   │   │   ├── GraphQlConfig.java
│   │   │   ├── ConfigReloadConfig.java
│   │   │   ├── P6SpyConfig.java
│   │   │   ├── DevToolsConfig.java
│   │   │   ├── RedisConfig.java
│   │   │   ├── KafkaConfig.java
│   │   │   └── RabbitMQConfig.java
│   │   ├── security/jwt/
│   │   │   ├── JwtProperties.java
│   │   │   ├── JwtTokenProvider.java
│   │   │   └── JwtAuthenticationFilter.java
│   │   ├── admin/
│   │   │   ├── AdminProperties.java
│   │   │   ├── AdminSecurityConfig.java
│   │   │   ├── AdminController.java
│   │   │   ├── SettingsService.java
│   │   │   ├── PropertyEntry.java
│   │   │   └── PropertySection.java
│   │   └── messaging/
│   │       ├── kafka/
│   │       │   ├── KafkaProducerService.java
│   │       │   └── KafkaConsumerService.java
│   │       └── rabbitmq/
│   │           ├── RabbitMQProducerService.java
│   │           └── RabbitMQConsumerService.java
│   └── resources/
│       ├── application.properties
│       ├── logback-spring.xml
│       ├── static/
│       │   └── css/
│       │       └── admin.css
│       └── templates/
│           ├── login.html
│           └── settings.html
└── test/
    └── java/com/spring/lica/
        └── LicaApplicationTests.java
```

## 시작하기

### 요구사항

- JDK 21

### 빌드

```bash
./gradlew build
```

### 실행

```bash
./gradlew bootRun
```

애플리케이션은 `http://localhost:8080`에서 실행됩니다.

### H2 콘솔

H2 데이터베이스 콘솔은 `http://localhost:8080/h2-console`에서 접근할 수 있습니다.

- JDBC URL: `jdbc:h2:mem:licadb`
- Username: `sa`
- Password: (비어 있음)

## JWT 인증

JWT 기반 Stateless 인증이 기본으로 활성화되어 있습니다.

- **공개 엔드포인트**: `/api/auth/**`, `/h2-console/**`
- **인증 필요**: 그 외 모든 엔드포인트
- **토큰 전달**: `Authorization: Bearer <token>` 헤더

### 설정 (`application.properties`)

```properties
jwt.secret=your-256-bit-secret-key-here-change-in-production
jwt.expiration=3600000
```

> 프로덕션 환경에서는 반드시 `jwt.secret` 값을 변경하세요.

## 선택적 모듈

모든 선택적 모듈은 `@ConditionalOnProperty`로 제어됩니다. `application.properties`에서 `enabled=true/false`로 변경하여 활성화/비활성화할 수 있습니다.

### 기본 포함 라이브러리

다음 라이브러리는 토글 없이 항상 포함됩니다:

- **Validation** (`spring-boot-starter-validation`) - `@Valid`, `@NotBlank`, `@Size` 등 Bean Validation
- **Lombok** - `@Getter`, `@Builder`, `@Slf4j` 등 보일러플레이트 제거
- **MapStruct** (`1.5.5.Final`) - Entity/DTO 변환 매퍼 코드 자동 생성 (컴파일 타임)
- **Configuration Processor** - `@ConfigurationProperties` IDE 자동완성 지원

### JDBC

```properties
app.module.jdbc.enabled=true
```

기본 활성화. `DataSource`, `JdbcTemplate`, `TransactionManager`, H2 콘솔이 자동 구성됩니다. JPA 없이 순수 JDBC만 사용할 때도 이 모듈만 활성화하면 됩니다.

### JPA

```properties
app.module.jpa.enabled=true
```

기본 활성화. Hibernate JPA 자동 구성 및 `@EnableJpaRepositories`가 활성화됩니다. JDBC 모듈이 함께 활성화되어야 합니다.

### QueryDSL

```properties
app.module.querydsl.enabled=true
```

기본 비활성화. 활성화 시 `JPAQueryFactory` 빈이 등록됩니다. JPA 모듈이 함께 활성화되어야 합니다.

### Actuator

```properties
app.module.actuator.enabled=true
```

기본 비활성화. 활성화 시 `/actuator/health`, `/actuator/info` 등 모니터링 엔드포인트가 노출됩니다. `management.endpoints.web.exposure.include`로 노출할 엔드포인트를 조정할 수 있습니다.

### OpenAPI (Swagger)

```properties
app.module.openapi.enabled=true
```

기본 비활성화. 활성화 시 `/swagger-ui/index.html`에서 API 문서를 확인할 수 있습니다. `springdoc.api-docs.enabled`와 `springdoc.swagger-ui.enabled` 속성과 연동됩니다.

### Flyway

```properties
app.module.flyway.enabled=true
```

기본 비활성화. 활성화 시 `src/main/resources/db/migration/` 경로의 SQL 스크립트로 DB 스키마를 관리합니다. Flyway 사용 시 `spring.jpa.hibernate.ddl-auto`를 `validate` 또는 `none`으로 변경하세요.

### Mail

```properties
app.module.mail.enabled=true
spring.mail.host=smtp.example.com
spring.mail.port=587
```

기본 비활성화. 활성화 시 `JavaMailSender` 빈이 자동 구성됩니다.

### AOP

```properties
app.module.aop.enabled=true
```

기본 비활성화. 활성화 시 `@Aspect`, `@EnableAspectJAutoProxy`를 사용한 커스텀 AOP가 동작합니다. 참고: `@Transactional` 등 Spring 내장 AOP는 이 모듈과 무관하게 동작합니다.

### WebSocket

```properties
app.module.websocket.enabled=true
```

기본 비활성화. 활성화 시 JSR 356 WebSocket 및 STOMP 메시징을 사용할 수 있습니다.

### OAuth2 Resource Server

```properties
app.module.oauth2.enabled=true
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://your-auth-server.com
```

기본 비활성화. 활성화 시 외부 IdP(Keycloak, Auth0 등)의 JWT 토큰을 검증하는 리소스 서버가 구성됩니다.

### Thymeleaf

```properties
app.module.thymeleaf.enabled=true
```

기본 비활성화. 활성화 시 Thymeleaf 템플릿 엔진이 구성됩니다. `src/main/resources/templates/` 경로의 `.html` 파일을 뷰로 사용합니다.

### GraphQL

```properties
app.module.graphql.enabled=true
```

기본 비활성화. 활성화 시 `/graphql` 엔드포인트가 구성됩니다. 스키마 파일은 `src/main/resources/graphql/` 경로에 `.graphqls` 확장자로 작성합니다.

### Config Reload (설정 자동 리로드)

```properties
app.module.config-reload.enabled=true
app.module.config-reload.watch-path=./application.properties
app.module.config-reload.interval=5000
```

기본 비활성화. Spring Cloud Context의 `@RefreshScope`를 활용하여 설정 파일 변경 시 해당 빈을 자동으로 재생성합니다.

- `@RefreshScope` 선언된 빈 → 설정 변경 시 자동 재생성
- `@ConfigurationProperties` 빈 → 속성 자동 리바인딩
- `watch-path` 설정 시 → 파일 변경 자동 감지 (주기: `interval`ms)
- `watch-path` 미설정 시 → `POST /actuator/refresh`로 수동 트리거 (Actuator 모듈 필요)

### P6Spy

```properties
app.module.p6spy.enabled=true
```

기본 비활성화. 활성화 시 SQL 쿼리 로그에 바인딩 파라미터 값이 함께 출력됩니다. 개발/디버깅 용도로 사용하세요.

### DevTools

```properties
app.module.devtools.enabled=true
```

기본 활성화. 개발 시 코드 변경 감지 자동 재시작 및 LiveReload를 제공합니다. 프로덕션 JAR에서는 자동으로 비활성화됩니다.

### Redis (캐싱 + 세션)

```properties
app.module.redis.enabled=true
spring.data.redis.host=localhost
spring.data.redis.port=6379
```

활성화 시 `RedisTemplate`, `CacheManager`, Redis HTTP 세션이 자동 구성됩니다.

### Kafka

```properties
app.module.kafka.enabled=true
spring.kafka.bootstrap-servers=localhost:9092
spring.kafka.consumer.group-id=lica-group
```

활성화 시 `KafkaTemplate`, `KafkaListenerContainerFactory`, Producer/Consumer 서비스가 구성됩니다.

### RabbitMQ

```properties
app.module.rabbitmq.enabled=true
spring.rabbitmq.host=localhost
spring.rabbitmq.port=5672
spring.rabbitmq.username=guest
spring.rabbitmq.password=guest
```

활성화 시 Queue(`lica-queue`), TopicExchange(`lica-exchange`), Producer/Consumer 서비스가 구성됩니다.

## Admin UI

### 접속

- **로그인 페이지**: `http://localhost:8080/login`
- **관리 콘솔**: `http://localhost:8080/admin/console` (로그인 후 기본 이동)
- **설정 페이지**: `http://localhost:8080/admin/settings`

### 기본 계정

```properties
app.admin.username=admin
app.admin.password=admin
```

### Admin Console

SPA 스타일의 관리 콘솔로, 좌측 사이드바 + 우측 메인 콘텐츠 구성입니다. Thymeleaf 레이아웃 + 바닐라 JS `fetch()`로 기존 `/admin/api/*` REST API를 호출합니다.

| 탭 | API | 기능 |
|---|---|---|
| Dashboard | `GET /admin/api/stats` | 통계 카드 (사용자, 세션, 클라이언트, IdP 수), 최근 이벤트 미리보기 |
| Users | `GET /admin/api/users` | 사용자 테이블, 잠금/해제, 비밀번호 초기화, 세션 만료 |
| Clients | `GET /admin/api/clients` | OAuth 클라이언트 테이블, 생성/수정/삭제 |
| Sessions | `GET /admin/api/sessions` | 활성 SSO 세션 테이블, 세션 폐기 |
| Events | `GET /admin/api/events` | 감사 로그 테이블, event_type/username 필터, 페이지네이션 |
| Identity Providers | `GET /admin/api/identity-providers` | IdP 테이블, 생성/수정/삭제 |

사이드바 하단의 **Settings** 링크로 기존 프레임워크 설정 페이지(`/admin/settings`)로 이동할 수 있습니다.

### Settings 페이지

웹 기반 관리 페이지에서 `application.properties`의 모든 설정을 읽고 수정할 수 있습니다.

```properties
app.admin.settings-file=src/main/resources/application.properties
```

1. 모든 프로퍼티를 섹션별로 확인/수정 가능
2. boolean 값(`true`/`false`)은 드롭다운으로, 그 외 값은 텍스트 입력으로 표시
3. **Save** 버튼 클릭 시 파일 저장 후 Config Reload 모듈이 활성화되어 있으면 자동으로 설정이 리로드됨

### 보안

- Admin UI는 세션 기반 폼 로그인(`@Order(1)`)으로 동작하며, API용 JWT 인증과 독립적으로 구성됩니다
- `/admin/**` 경로는 `ROLE_ADMIN` 권한이 필요합니다
- Thymeleaf 모듈(`app.module.thymeleaf.enabled=true`)이 활성화되어야 합니다

> 프로덕션 환경에서는 반드시 `app.admin.password`를 변경하세요.

## 로깅

`logback-spring.xml`로 로그 포맷과 출력 대상이 설정되어 있습니다.

### 로그 포맷

```
2026-01-15 10:30:45.123 DEBUG [http-nio-8080-exec-1] com.spring.lica.config.SecurityConfig    : message
```

### 프로파일별 동작

| Profile | 출력 대상 |
|---|---|
| `default` / `local` / `dev` | Console (컬러) |
| `prod` | Console + `./logs/{앱명}.log` + `./logs/{앱명}-error.log` |

파일 로그: 일별 로테이션, 파일당 100MB, 30일 보관, 총 1GB 제한

### SQL 로깅

Hibernate SQL과 바인딩 파라미터가 logback 포맷으로 출력됩니다:

```
DEBUG org.hibernate.SQL                          : select u1_0.id, u1_0.name from users u1_0 where u1_0.id=?
TRACE org.hibernate.orm.jdbc.bind                : binding parameter (1:BIGINT) <- [42]
```

`spring.jpa.properties.hibernate.format_sql=true`로 SQL이 정렬되어 출력됩니다.

## 라이선스

[MIT License](LICENSE)
