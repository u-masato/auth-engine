// Package storage は、Store Port の実装（Adapter）が返すセンチネルエラーを定義する葉パッケージである。
//
// インターフェースや保存対象の型はここには置かない。Store インターフェースは
// それを使う文脈パッケージ（client, authorization, grant, token）が定義し、
// ルートパッケージ authengine がそれらを合成する（docs/adr/0007-package-layout.md §2）。
//
// Adapter 実装者への契約: 各 Store メソッドはそれ単体で原子的でなければならない。
// エンジンは複数のメソッド呼び出しをまたいで一貫性を期待しない
// （docs/adr/0005-storage-port.md §1）。
//
// Client の更新と削除（client.Store の UpdateClient / DeleteClient）も同じ契約に従う。
//
//   - UpdateClient は保存済みの Profile との照合と更新を 1 つの操作で行う。Profile が違えば
//     ErrStateConflict を返し、何も変更しない（docs/adr/0004-client-profiles.md §4）。
//   - DeleteClient は Client の削除、その Client の全 Grant の失効（配下の全 Token Family・
//     全トークンを含む。RevokeGrant と同じ連鎖）、その Client の Authorization Code の削除を
//     1 つの操作で行う。存在しなければ ErrNotFound を返し、何も変更しない。
//     Grant の行は失効済みとして残す。同じ client_id で Client を作り直しても Grant はそれだけでは
//     active に戻らず、同意をやり直したときに UpsertGrant が新しい scope だけで再び active にする
//     （grant.Merge）。Code を削除するのは、その再同意で同じ Grant が active に戻ったとき、
//     削除前に発行した未使用の Code が交換できてしまうのを防ぐためである。
//     ただし進行中の Transaction には触れない。削除前に同意が済んだ Transaction を削除後に Resume
//     すると、Grant が active に戻り、削除後の Code が発行される。そのため同じ client_id の
//     作り直しは、Transaction の有効期限が過ぎてから行う前提とする。
package storage
