// Package storage は、Store Port の実装（Adapter）が返すセンチネルエラーを定義する葉パッケージである。
//
// インターフェースや保存対象の型はここには置かない。Store インターフェースは
// それを使う文脈パッケージ（client, authorization, grant, token）が定義し、
// ルートパッケージ authengine がそれらを合成する（docs/adr/0007-package-layout.md §2）。
//
// Adapter 実装者への契約: 各 Store メソッドはそれ単体で原子的でなければならない。
// エンジンは複数のメソッド呼び出しをまたいで一貫性を期待しない
// （docs/adr/0005-storage-port.md §1）。
package storage
