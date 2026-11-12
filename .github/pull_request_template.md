## 何を・なぜ

<!-- 対応する issue、ロードマップのタスク番号、関係する仕様と節（例: RFC 6749 §4.1.2.1） -->

## 確認したこと

- [ ] `make vet test` が通る
- [ ] `make lint` が通る（govulncheck が手元の Go の脆弱性で落ちる場合は CI の結果で確認）
- [ ] 変更に対応する正常系・異常系のテストを足した
- [ ] Store の振る舞いを変えた場合、`storage/storagetest` に契約テストを足し、全 Adapter で通した
- [ ] 外部入力を解析・照合する関数を足した場合、Fuzz テストを足した
- [ ] 判断を書いたコメントに仕様の節番号を添えた

## 文書

- [ ] 設計を変えた場合、ADR を追加・修正した（不変条件の変更は先に issue で合意済み）
- [ ] HTTP の形を変えた場合、`docs/interaction-api.md` を直した
- [ ] `Config` や公開 API を変えた場合、`docs/embedding.md` と `example_test.go` を直した
- [ ] 該当しない
