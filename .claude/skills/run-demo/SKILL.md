---
name: run-demo
description: auth-engine のデモサーバー（examples/standalone の server = エンジン + Interaction API + デモログイン画面）をバックグラウンドで起動・停止・確認し、cli-client で Authorization Code + PKCE のフローを回す。「デモ起動して」「サーバー立てて」「動かして見せて」「ログイン画面を見たい」「トークン取れるか試して」「ポートが使われてる」「DB をリセットして」など、このリポジトリのアプリを実際に動かす話が出たら、go run を手で打つ前に必ずこの skill を使う。/run からの起動もこの skill に従う。
---

# デモサーバーの起動

`scripts/demo.sh` が起動・停止・状態確認・フロー実行をまとめている。手で `go run` するより、
このスクリプトを使う方が確実に速い。理由は 3 つある。

- `go run` をバックグラウンドにすると子プロセスの PID が取れず止められなくなる。スクリプトは
  先に `go build` してバイナリを直接起動し、PID をファイルに残す。
- 起動は 3 ポート（既定 8080 / 8081 / 8082）を同時に取る。空きを先に確認しないと、片方だけ
  取れて失敗した理由が分かりにくい。
- DB・署名鍵・ログを `examples/standalone/.demo/`（gitignore 済み）に集めるので、作業ツリーを
  汚さず、`reset` で初期状態に戻せる。

## 使い方

```bash
S=.claude/skills/run-demo/scripts/demo.sh   # リポジトリルートから
$S start                  # 起動して ready まで待つ。URL・PID・ログの場所を表示
$S start -auto-approve    # 画面を出さず demo-user で全承認（自動テスト・動作確認向け）
$S status                 # 起動中か、Discovery に届くか、ポートを誰が使っているか
$S flow                   # cli-client で認可フロー。-auto-approve 起動なら承認まで全自動
$S flow-wait              # ブラウザで承認した後、トークンの結果を表示
$S logs [N]               # サーバーログの末尾
$S stop                   # 停止
$S reset                  # 停止して auth.db と keys.json を削除（次回起動で再生成。署名鍵も変わる）
```

`start` の残りの引数はそのまま server に渡る（`-clients ../../conformance/clients.json` など）。
ポートを変えるときは `DEMO_PORT_BASE=8090 $S start` のように環境変数で指定する。
公開 = base、Interaction API = base+1、ログイン画面 = base+2 で、issuer と login-url も追従する。

## 判断のしかた

**何を求められているかで起動モードを選ぶ。**
- 「動くか確かめて」「トークン取れるか」のように結果だけ欲しい → `start -auto-approve` して `flow`。
  承認画面を介さず access_token / id_token / UserInfo まで一気に出る。
- 「ログイン画面を見たい」「承認の流れを確認したい」→ 通常の `start` のあと `flow`。表示された
  authorization_url をブラウザ（ブラウザペインがあればそこ）で開き、ユーザー名を入れて承認し、
  `flow-wait` で結果を見る。ユーザー自身に操作してもらう場合は URL とその手順を伝える。
  `http://localhost:8082/login` を直接開いても 400 になる（Resume Token がないと画面を出さない
  ヘッドレス契約のため）。「ブラウザで見られる URL」を聞かれたら、Discovery の URL と一緒に
  `flow` が出す authorization_url を渡すのが正しい答えで、`/login` 単体を案内しない。

**ポートが使われていたら、勝手に殺さない。** `start` は使用中のプロセス名と PID を表示して
止まる。それが以前のデモ（`server` や `cli-client`）なら `stop` で片付く。別のものなら
ユーザーに伝えて、`DEMO_PORT_BASE` で避けるか止めてもらうかを選んでもらう。

**挙動がおかしいときは `logs` を先に見る。** slog のテキスト形式で、`msg=ready` の行に issuer と
auto_approve が出る。クライアント登録や鍵の生成も起動ログに残る。

## 報告すること

起動したら、次をそのまま伝える。URL は貼れば開ける形にする。

- issuer と Discovery の URL、ログイン画面の URL
- auto_approve の有無（true なら「誰でも demo-user として承認される」ことを一言添える）
- ログファイルの場所と、止め方（`demo.sh stop`）

フローを回したら、token_type / scope と、どのトークン（access / refresh / id）が出たかを要約する。
トークンの値そのものは長いので、ユーザーが求めない限り全文を貼らない。

## 片付け

作業が終わっても、ユーザーが「止めて」と言うまでサーバーは起動したままでよい。続けて試す
ことが多いからだ。ただし終了報告には起動中であることと止め方を必ず書く。クライアント登録を
やり直したいとき（`-clients` の内容を変えたときなど）は、Store に更新操作がないので `reset` で
DB を作り直す。
