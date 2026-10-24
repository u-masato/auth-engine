# OAuth/OIDC認可サーバーOSSの準拠仕様一覧

2026年10月24日時点のIETF RFC、OpenID Foundation、MCP公式仕様を基に整理しました。

今回の構想は、Goで実装するヘッドレスなOAuth/OIDCプロトコルエンジンです。認証・同意処理は外部化し、MCPやAIエージェント向けの認可にも対応することを目指します。

結論として、仕様を4段階に分けるのがよいと思います。

| 段階 | 対象              | 目標                     |
| -- | --------------- | ---------------------- |
| P0 | OAuth/OIDC Core | 一般的な認可サーバーとして利用可能      |
| P1 | MCP連携           | MCPクライアント・サーバーから利用可能   |
| P2 | 高度なOAuth拡張      | エージェント間の委譲や強固なセキュリティ   |
| P3 | 高保証・特殊用途        | FAPI、Federation、CIBAなど |

ここでいう準拠は、実装する仕様とプロファイルを明示し、その要求事項を満たすことです。RFC全体のあらゆる任意機能を実装するという意味ではありません。

## P0. OAuth/OIDCの基本仕様

初期リリースの対象

### OAuth 2.0

| 仕様                                                                             | 実装対象                                                                        | 優先度 |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | --- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html?utm_source=chatgpt.com) | Authorization Code、Token Endpoint、Client Credentials、Refresh Token、クライアント認証 | 必須  |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html?utm_source=chatgpt.com) | Bearer Tokenの取り扱い・エラー応答                                                     | 必須  |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html?utm_source=chatgpt.com) | PKCE（S256）、`code_verifier` の検証                                              | 必須  |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html?utm_source=chatgpt.com) | OAuth Security Best Current Practice                                        | 必須  |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html?utm_source=chatgpt.com) | Authorization Server Metadata、Discovery                                     | 必須  |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html?utm_source=chatgpt.com) | 認可レスポンスの `iss` によるAS Mix-Up対策                                               | 必須  |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html?utm_source=chatgpt.com) | Token Revocation Endpoint                                                   | 推奨  |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html?utm_source=chatgpt.com) | Token Introspection Endpoint                                                | 推奨  |

RFC 9700は2025年1月公開のセキュリティBCPです。RFC 6749をそのまま実装するだけではなく、このBCPで更新されたセキュリティ要件を反映する必要があります。


例えば、最初のリリースではImplicit GrantとResource Owner Password Credentials Grantを提供しない方針を推奨します。

### OpenID Connect

OIDCには独立した仕様書があり、RFC番号は付いていません。

| 仕様                                                                                                                    | 実装対象                                                                      |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html?utm_source=chatgpt.com)                         | ID Token、OIDC Authorization Code Flow、UserInfo、Claims、`nonce`、`auth_time` |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html?utm_source=chatgpt.com)               | `.well-known/openid-configuration`                                        |
| [OIDC Dynamic Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html?utm_source=chatgpt.com) | OIDCクライアントの動的登録（初期は任意）                                                    |

CoreとDiscoveryについては、2023年12月のErrata Set 2を取り込んだFinal仕様を基準にできます。


最初はOIDCのAuthorization Code Flowに限定することを推奨します。Implicit FlowやHybrid Flowは後回しにします。

### JWT・暗号処理の基盤

| 仕様                                                                             | 実装対象                             |
| ------------------------------------------------------------------------------ | -------------------------------- |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html?utm_source=chatgpt.com) | JSON Web Signature（JWS）          |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html?utm_source=chatgpt.com) | JSON Web Key（JWK / JWKS）         |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html?utm_source=chatgpt.com) | JSON Web Algorithms（JWA）         |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html?utm_source=chatgpt.com) | JSON Web Token（JWT）              |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html?utm_source=chatgpt.com) | JWTのセキュリティベストプラクティス              |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html?utm_source=chatgpt.com) | JWT形式のOAuth Access Token（JWT採用時） |

ここは暗号プリミティブを自作するのではなく、十分に検証されたライブラリを採用します。

なお、JWT Access Tokenは必須ではありません。Opaque TokenだけでもOAuth認可サーバーは実装できます。

## P1. MCPに対応するための仕様

ここはOSSの差別化にもつながる領域です。

基準にするのは、[MCP Authorization Specification（2026-07-28）](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization?utm_source=chatgpt.com) です。

### 必要な仕様

| 仕様                                                                                                                            | 実装対象                                       | 優先度       |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | --------- |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html?utm_source=chatgpt.com)                                                | Resource Indicators。Access Tokenの利用対象を指定   | 必須        |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html?utm_source=chatgpt.com)                                                | Protected Resource Metadata。MCPサーバーの認可情報公開 | MCP連携には必須 |
| [CIMD（Internet-Draft）](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/?utm_source=chatgpt.com) | Client ID Metadata Documentによるクライアント識別     | 強く推奨      |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html?utm_source=chatgpt.com)                                                | Dynamic Client Registration（DCR）           | 互換性目的     |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html?utm_source=chatgpt.com)                                                | CLI・デスクトップなどNative AppのOAuth対応             | 推奨        |

MCPの2026年7月版では、CIMDが推奨され、DCRは後方互換性のために残る非推奨方式になっています。また、Resource IndicatorsとAudience検証が重要な要件です。

[image](https://www.google.com/s2/favicons?domain=https://modelcontextprotocol.io\&sz=32)

Model Context Protocol

ただし責務の違いに注意が必要です。

- RFC 8414は、認可サーバーが自分自身のメタデータを公開するための仕様。
- RFC 9728は、Resource Serverが自分のメタデータを公開するための仕様。
- RFC 8707は、認可サーバーがトークンを発行するとき、対象リソースを識別するための仕様。

したがって、プロトコルエンジンにはRFC 8707の処理を実装し、MCP Resource Server用のミドルウェアにRFC 9728への対応を持たせる設計が自然です。

### MCP実装で特に守りたい不変条件

例えば、MCPクライアントが次のパラメータを送信します。

```
GET /authorize?
  response_type=code&
  client_id=example&
  resource=https://mcp.example.com&
  scope=files:read&
  code_challenge=...
```

認可サーバーは `resource` を検証し、発行するAccess Tokenを対象リソースに結びつけます。

そして、MCPサーバー側は、そのAccess TokenのAudienceが自分自身を指していることを確認します。

つまり、別のMCPサーバー向けに発行されたトークンを受け入れないようにします。これはトークンの形式がJWTでもOpaqueでも守るべき条件です。

[image](https://www.google.com/s2/favicons?domain=https://modelcontextprotocol.io\&sz=32)

Model Context Protocol



### OAuth 2.1について

[OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/?utm_source=chatgpt.com) は、2026年10月時点でもRFCではなくInternet-Draftです。確認できる版は2026年9月2日の `draft-ietf-oauth-v2-1-16` です。

[image](https://www.google.com/s2/favicons?domain=https://datatracker.ietf.org\&sz=32)

The OAuth 2.1 Authorization Framework



MCP仕様はOAuth 2.1を参照していますが、実装にあたってはRFC 6749とRFC 9700を基盤にし、OAuth 2.1 Draftとの差分を追跡するのがよいでしょう。

## P2. 高度なOAuth・エージェント認可

ここからは、OSSの独自性を高めるための機能です。

### トークン・権限委譲

| 仕様                                                                             | 実装対象                                                           | 優先度 |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------- | --- |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html?utm_source=chatgpt.com) | Token Exchange。別のAudience向けトークン発行、Impersonation・Delegation     | 高   |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html?utm_source=chatgpt.com) | Rich Authorization Requests。`authorization_details` による詳細な権限表現 | 高   |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html?utm_source=chatgpt.com) | DPoP。公開鍵とAccess Tokenの紐付け、Proof検証                              | 高   |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html?utm_source=chatgpt.com) | JWTによるクライアント認証・Authorization Grant                             | 高   |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html?utm_source=chatgpt.com) | Device Authorization Grant。入力制限のあるデバイス向け                       | 中   |

RFC 8693では、`subject_token` と `actor_token` を用いた委譲が扱われています。RFC 9396はScopeでは表現しきれない細かな権限をJSONで伝えるための仕様です。

ただし、RFC 8693は交換元トークンの失効が交換先に自動伝播することまでは保証しません。この部分はドメインポリシーとして明示的に設計する必要があります。

### 認可リクエストの保護

| 仕様                                                                               | 実装対象                                         | 優先度 |
| -------------------------------------------------------------------------------- | -------------------------------------------- | --- |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html?utm_source=chatgpt.com)   | PAR。認可リクエストをバックチャネルで送信                       | 高   |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html?utm_source=chatgpt.com)   | JAR。JWTで認可リクエストを署名・保護                        | 中   |
| [JARM](https://openid.net/specs/oauth-v2-jarm-final.html?utm_source=chatgpt.com) | JWTによる認可レスポンスの保護                             | 中   |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html?utm_source=chatgpt.com)   | mTLS Client Authenticationと証明書拘束Access Token | 中   |

PARは比較的早期に実装したい仕様です。認可トランザクションのモデルを改善するうえでも役立ちます。

JAR、PAR、JARMは相互に関連しますが、それぞれ独立した役割があります。JARはリクエスト内容の保護、PARはバックチャネルによる提出、JARMはレスポンス内容の保護です。

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org\&sz=32)

## 5. 実装順序と依存関係

単にRFC単位でコードを作るより、次の順番でドメインの責務を増やす方が合理的です。

Phase 1 — OAuth Core

RFC 6749 / 6750 / 7636 / 9700 / 8414 / 9207

Authorization、Client、Grant、Tokenのモデルを確立

Phase 2 — OIDC / Token Lifecycle

OIDC Core / Discovery、RFC 7009 / 7662

ID Token、UserInfo、Revocation、Introspection

Phase 3 — MCP対応

RFC 8707 / 9728、CIMD

Resource単位のトークン発行とMCPクライアント登録

Phase 4 — 高度な委譲とセキュリティ

RFC 8693 / 9396 / 9449 / 9126 / 7523

Token Exchange、RAR、DPoP、PAR、JWT Client Authentication

Phase 5 — 高保証プロファイル

FAPI 2.0、JAR、mTLSなど

特定プロファイルの追加要求事項を実装・検証

## 6. RFC準拠をどう検証するか

今回の開発では、仕様の実装と同時にテストを構築することを強く推奨します。
最低限、次の3種類です。

- Protocol Conformance Tests：OAuth/OIDCの正しいレスポンス、エラー処理、Discoveryの整合性を検証する。
- Security Tests：PKCE Downgrade、Code Replay、Refresh Token Replay、Redirect URI不一致、署名アルゴリズム混同などを検証する。
- Concurrency Tests：認可コードの同時交換、Refresh Token Rotationの競合、Grant失効とトークン発行の競合を検証する。

外部検証には [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite?utm_source=chatgpt.com) を活用します。MCPについても、公式仕様に対する相互運用テストを別に用意する必要があります。
