-- +goose Up
-- Client ごとの Grant 一覧（grant.Store.ListGrantsByClient。ADR-0005 §3）。
-- 一覧は subject をバイト列として比べた昇順で返す。一意制約 (client_id, subject) の索引はデータベースの
-- 既定の照合順序なので、COLLATE "C" の並べ替えには使えない。同じ列で照合順序だけを変えた索引を置く。
CREATE INDEX grants_client_subject_c ON grants (client_id, subject COLLATE "C");

-- +goose Down
DROP INDEX grants_client_subject_c;
