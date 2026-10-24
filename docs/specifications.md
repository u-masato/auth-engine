# 準拠仕様一覧

- 状態: 採用（2026-10-24 合意）
- 基準日: 2026-10-24（IETF RFC、OpenID Foundation、MCP 公式仕様の当日時点の版）

Protocol Engine が準拠する仕様を 4 段階に分けて列挙する。ここでいう「準拠」は、実装する仕様とプロファイルを明示し、その要求事項を満たすことを指す。各 RFC の任意機能をすべて実装するという意味ではない。

マイルストーンへの割り当ては [roadmap.md](roadmap.md)、P0 で提供しないものは [ADR-0001](adr/0001-scope-and-principles.md) を参照。

| 段階 | 対象 | 目標 |
| --- | --- | --- |
| P0 | OAuth / OIDC Core | 一般的な認可サーバーとして使える |
| P1 | MCP 連携 | MCP クライアント・サーバーから使える |
| P2 | 高度な OAuth 拡張 | エージェント間の委譲と強固なセキュリティ |
| P3 | 高保証・特殊用途 | FAPI、Federation、CIBA など |

## P0. OAuth / OIDC の基本仕様

初期リリースの対象。

### OAuth 2.0

| 仕様 | 実装対象 | 優先度 |
| --- | --- | --- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) | Authorization Code、Token Endpoint、Client Credentials、Refresh Token、クライアント認証 | 必須 |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) | Bearer Token の取り扱いとエラー応答 | 必須 |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | PKCE（S256）、`code_verifier` の検証 | 必須 |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | OAuth 2.0 Security Best Current Practice | 必須 |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) | Authorization Server Metadata（Discovery） | 必須 |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) | 認可レスポンスの `iss` による AS Mix-Up 対策 | 必須 |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) | Token Revocation | 推奨（M2 で必須に格上げ、ADR-0006） |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) | Token Introspection | 推奨（M2 で必須に格上げ、ADR-0006） |

- RFC 9700（2025 年 1 月公開）は RFC 6749 のセキュリティ要件を更新する。RFC 6749 だけでなく、この BCP の要件を満たす。
- Implicit Grant と Resource Owner Password Credentials Grant は提供しない。

### OpenID Connect

OIDC の仕様は OpenID Foundation が発行しており、RFC 番号はない。

| 仕様 | 実装対象 |
| --- | --- |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token、Authorization Code Flow、UserInfo、Claims、`nonce`、`auth_time` |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OIDC Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | クライアントの動的登録（P0 では任意） |

- Core と Discovery は Errata Set 2（2023 年 12 月）を取り込んだ Final 版を基準にする。
- Authorization Code Flow に限定する。Implicit Flow と Hybrid Flow は扱わない。

### JWT・暗号処理の基盤

| 仕様 | 実装対象 |
| --- | --- |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) | JSON Web Signature（JWS） |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) | JSON Web Key（JWK / JWKS） |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | JSON Web Algorithms（JWA） |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) | JSON Web Token（JWT） |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | JWT Best Current Practices |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) | JWT 形式の Access Token（採用する場合のみ） |

- 暗号プリミティブは自作せず、検証済みのライブラリを使う（go-jose v4、ADR-0002）。
- JWT Access Token は必須ではない。Access Token は Opaque を既定とする（ADR-0006）。

## P1. MCP 連携

基準は [MCP Authorization Specification（2026-07-28）](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)。

| 仕様 | 実装対象 | 優先度 |
| --- | --- | --- |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Resource Indicators。Access Token の利用対象を指定する | 必須 |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Protected Resource Metadata。MCP サーバーが認可情報を公開する | MCP 連携には必須 |
| [CIMD（Internet-Draft）](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) | Client ID Metadata Document によるクライアント識別 | 強く推奨 |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) | Dynamic Client Registration（DCR） | 互換性目的 |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) | CLI・デスクトップなど Native App の OAuth | 推奨 |

MCP の 2026-07-28 版では CIMD が推奨で、DCR は後方互換のために残る非推奨方式である。Resource Indicators と Audience 検証が重要な要件になる。

### 責務の分担

| 仕様 | 誰が何をするか | 置き場所 |
| --- | --- | --- |
| RFC 8414 | 認可サーバーが自身のメタデータを公開する | Protocol Engine |
| RFC 8707 | 認可サーバーがトークン発行時に対象リソースを識別する | Protocol Engine |
| RFC 9728 | Resource Server が自身のメタデータを公開する | MCP Resource Server 用ミドルウェア |

### 守る不変条件: トークンは対象リソースに結びつける

MCP クライアントは次のように `resource` を送る。

```
GET /authorize?
  response_type=code&
  client_id=example&
  resource=https://mcp.example.com&
  scope=files:read&
  code_challenge=...
```

1. 認可サーバーは `resource` を検証し、発行する Access Token を対象リソースに結びつける。
2. MCP サーバーは Access Token の Audience が自分自身であることを確認する。

これにより、別の MCP サーバー向けに発行されたトークンを受け入れない。トークン形式が JWT でも Opaque でも守る。

### OAuth 2.1 の扱い

[OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) は 2026-10-24 時点で RFC ではなく Internet-Draft（最新は 2026-09-02 の `draft-ietf-oauth-v2-1-16`）。MCP 仕様は OAuth 2.1 を参照するが、本実装は RFC 6749 と RFC 9700 を基盤とし、OAuth 2.1 Draft との差分を追跡する。

## P2. 高度な OAuth・エージェント認可

### トークン・権限の委譲

| 仕様 | 実装対象 | 優先度 |
| --- | --- | --- |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) | Token Exchange。別の Audience 向けトークン発行、Impersonation と Delegation | 高 |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) | Rich Authorization Requests。`authorization_details` による詳細な権限表現 | 高 |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | DPoP。公開鍵と Access Token の紐付け、Proof 検証 | 高 |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | JWT によるクライアント認証と Authorization Grant | 高 |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) | Device Authorization Grant（入力制限のあるデバイス向け） | 中 |

- RFC 8693 は `subject_token` と `actor_token` で委譲を表す。RFC 9396 は Scope で表しきれない権限を JSON で伝える。
- RFC 8693 は、交換元トークンの失効が交換先へ自動で伝播することを保証しない。伝播させるかはドメインポリシーとして明示的に設計する。

### 認可リクエスト・レスポンスの保護

| 仕様 | 実装対象 | 優先度 |
| --- | --- | --- |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) | PAR。認可リクエストをバックチャネルで提出する | 高 |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | JAR。認可リクエストを JWT で署名・保護する | 中 |
| [JARM](https://openid.net/specs/oauth-v2-jarm-final.html) | 認可レスポンスを JWT で保護する | 中 |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) | mTLS クライアント認証と証明書拘束 Access Token | 中 |

- JAR・PAR・JARM は関連するが役割は独立している。JAR はリクエスト内容、PAR は提出経路、JARM はレスポンス内容を保護する。
- PAR は認可トランザクションのモデル改善にも役立つため、P2 の中では早めに実装する。

## P3. 高保証・特殊用途

FAPI 2.0、OpenID Federation、CIBA など、特定プロファイルの追加要求事項を実装・検証する。対象と範囲は P2 の完了後に決める。

## 実装順序

RFC 単位でコードを足すのではなく、ドメインの責務を段階的に増やす。マイルストーン（M1〜M4）への対応と差分は [roadmap.md](roadmap.md) に記録している。

| Phase | 主な仕様 | 増える責務 |
| --- | --- | --- |
| 1. OAuth Core | RFC 6749 / 6750 / 7636 / 9700 / 8414 / 9207 | Authorization、Client、Grant、Token のモデル |
| 2. OIDC / Token Lifecycle | OIDC Core / Discovery、RFC 7009 / 7662 | ID Token、UserInfo、Revocation、Introspection |
| 3. MCP 対応 | RFC 8707 / 9728、CIMD | Resource 単位のトークン発行、MCP クライアントの登録 |
| 4. 高度な委譲とセキュリティ | RFC 8693 / 9396 / 9449 / 9126 / 7523 | Token Exchange、RAR、DPoP、PAR、JWT Client Authentication |
| 5. 高保証プロファイル | FAPI 2.0、JAR、mTLS など | 特定プロファイルの追加要求事項 |

## 準拠の検証

仕様の実装と同時にテストを作る。最低限、次の 3 種類を用意する。

| 種類 | 検証する内容 |
| --- | --- |
| Protocol Conformance | OAuth / OIDC の正しいレスポンス、エラー処理、Discovery の整合性 |
| Security | PKCE Downgrade、Code Replay、Refresh Token Replay、Redirect URI 不一致、署名アルゴリズム混同 |
| Concurrency | 認可コードの同時交換、Refresh Token Rotation の競合、Grant 失効とトークン発行の競合 |

外部検証には [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) を使う（手順は [conformance.md](conformance.md)）。MCP については、公式仕様に対する相互運用テストを別に用意する。
