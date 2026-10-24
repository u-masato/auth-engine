// Package memory は、エンジンの単体テスト用の In-Memory Store である。
//
// 契約テスト（storage/storagetest）を通すが、安全性の根拠は SQLite / PostgreSQL Adapter の
// テスト結果に置く（docs/adr/0005-storage-port.md §6）。本番では使わない。
//
// 全操作を 1 つの Mutex で直列化し、値は保存・取得時に深いコピーを行う。
// Adapter と同じく、呼び出し側が受け取った値を変更しても保存内容は変わらない。
package memory

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/token"
)

// Store は In-Memory の authengine.Store 実装。
type Store struct {
	mu sync.Mutex

	clients  map[string]*client.Client
	txns     map[string]*authorization.Transaction
	codes    map[string]*authorization.AuthorizationCode // key: Hash
	grants   map[string]*grant.Grant                     // key: ID
	grantIdx map[[2]string]string                        // (clientID, subject) → grant ID
	families map[string]*token.Family
	access   map[string]*token.AccessToken  // key: Hash
	refresh  map[string]*token.RefreshToken // key: Hash
}

var _ authengine.Store = (*Store)(nil)

// New は空の Store を返す。
func New() *Store {
	return &Store{
		clients:  map[string]*client.Client{},
		txns:     map[string]*authorization.Transaction{},
		codes:    map[string]*authorization.AuthorizationCode{},
		grants:   map[string]*grant.Grant{},
		grantIdx: map[[2]string]string{},
		families: map[string]*token.Family{},
		access:   map[string]*token.AccessToken{},
		refresh:  map[string]*token.RefreshToken{},
	}
}

// clone は JSON 経由の深いコピー。DB Adapter の直列化・復元と同じ境界を模倣する。
func clone[T any](v *T) *T {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic("memory: marshal: " + err.Error())
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		panic("memory: unmarshal: " + err.Error())
	}
	return out
}

// --- client.Store ---

func (s *Store) GetClient(_ context.Context, id string) (*client.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(c), nil
}

func (s *Store) CreateClient(_ context.Context, c *client.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.clients[c.ID]; dup {
		return storage.ErrAlreadyExists
	}
	s.clients[c.ID] = clone(c)
	return nil
}

// --- authorization.Store ---

func (s *Store) CreateTransaction(_ context.Context, txn *authorization.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.txns[txn.ID]; dup {
		return storage.ErrAlreadyExists
	}
	s.txns[txn.ID] = clone(txn)
	return nil
}

func (s *Store) GetTransaction(_ context.Context, id string) (*authorization.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.txns[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(t), nil
}

func (s *Store) TransitionTransaction(_ context.Context, id string, from, to authorization.Status, patch authorization.Patch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.txns[id]
	if !ok {
		return storage.ErrNotFound
	}
	if t.Status != from {
		return storage.ErrStateConflict
	}
	t.Status = to
	if patch.Outcome != nil {
		t.Outcome = clone(patch.Outcome)
	}
	if patch.Rejection != nil {
		t.Rejection = clone(patch.Rejection)
	}
	if patch.ResumeTokenHash != "" {
		t.ResumeTokenHash = patch.ResumeTokenHash
	}
	return nil
}

func (s *Store) CreateAuthorizationCode(_ context.Context, code *authorization.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.codes[code.Hash]; dup {
		return storage.ErrAlreadyExists
	}
	s.codes[code.Hash] = clone(code)
	return nil
}

// --- grant.Store ---

func (s *Store) UpsertGrant(_ context.Context, candidate *grant.Grant) (*grant.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := [2]string{candidate.ClientID, candidate.Subject}
	if id, ok := s.grantIdx[key]; ok {
		merged := grant.Merge(s.grants[id], candidate)
		s.grants[id] = clone(merged)
		return clone(merged), nil
	}
	if _, dup := s.grants[candidate.ID]; dup {
		return nil, storage.ErrAlreadyExists
	}
	s.grants[candidate.ID] = clone(candidate)
	s.grantIdx[key] = candidate.ID
	return clone(candidate), nil
}

func (s *Store) GetGrant(_ context.Context, id string) (*grant.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(g), nil
}

func (s *Store) FindGrant(_ context.Context, clientID, subject string) (*grant.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.grantIdx[[2]string{clientID, subject}]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(s.grants[id]), nil
}

func (s *Store) ListGrantsBySubject(_ context.Context, subject string) ([]*grant.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*grant.Grant{}
	for _, g := range s.grants {
		if g.Subject == subject {
			out = append(out, clone(g))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) RevokeGrant(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return storage.ErrNotFound
	}
	if !g.Active() {
		return nil
	}
	g.Status = grant.StatusRevoked
	g.RevokedAt = now
	for _, f := range s.families {
		if f.GrantID == id {
			s.revokeFamilyLocked(f, now)
		}
	}
	return nil
}

// --- token.Store ---

func (s *Store) ConsumeAuthorizationCode(_ context.Context, codeHash string, now time.Time) (*authorization.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[codeHash]
	if !ok {
		return nil, storage.ErrNotFound
	}
	if c.Consumed() {
		return clone(c), storage.ErrCodeAlreadyUsed
	}
	if c.Expired(now) {
		return nil, storage.ErrNotFound
	}
	c.ConsumedAt = now
	return clone(c), nil
}

func (s *Store) IssueTokens(_ context.Context, family *token.Family, access *token.AccessToken, refresh *token.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[family.GrantID]
	if !ok || !g.Active() {
		return storage.ErrGrantRevoked
	}
	if _, dup := s.families[family.ID]; dup {
		return storage.ErrAlreadyExists
	}
	if _, dup := s.access[access.Hash]; dup {
		return storage.ErrAlreadyExists
	}
	if refresh != nil {
		if _, dup := s.refresh[refresh.Hash]; dup {
			return storage.ErrAlreadyExists
		}
		s.refresh[refresh.Hash] = clone(refresh)
	}
	s.families[family.ID] = clone(family)
	s.access[access.Hash] = clone(access)
	return nil
}

func (s *Store) RotateRefreshToken(_ context.Context, oldHash string, next *token.RefreshToken, access *token.AccessToken, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.refresh[oldHash]
	if !ok {
		return storage.ErrNotFound
	}
	switch old.Status {
	case token.RefreshRotated:
		return storage.ErrTokenReused
	case token.RefreshRevoked:
		return storage.ErrFamilyRevoked
	}
	if !now.Before(old.ExpiresAt) {
		return storage.ErrNotFound
	}
	f, ok := s.families[old.FamilyID]
	if !ok || !f.Active() {
		return storage.ErrFamilyRevoked
	}
	if g, ok := s.grants[f.GrantID]; !ok || !g.Active() {
		return storage.ErrGrantRevoked
	}
	if _, dup := s.refresh[next.Hash]; dup {
		return storage.ErrAlreadyExists
	}
	if _, dup := s.access[access.Hash]; dup {
		return storage.ErrAlreadyExists
	}
	old.Status = token.RefreshRotated
	old.RotatedAt = now
	old.ReplacedByHash = next.Hash
	s.refresh[next.Hash] = clone(next)
	s.access[access.Hash] = clone(access)
	return nil
}

func (s *Store) LookupAccessToken(_ context.Context, hash string) (*token.AccessToken, *grant.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.access[hash]
	if !ok {
		return nil, nil, storage.ErrNotFound
	}
	g, ok := s.grants[t.GrantID]
	if !ok {
		return nil, nil, storage.ErrNotFound
	}
	return clone(t), clone(g), nil
}

func (s *Store) LookupRefreshToken(_ context.Context, hash string) (*token.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[hash]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(t), nil
}

func (s *Store) GetTokenFamily(_ context.Context, id string) (*token.Family, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.families[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return clone(f), nil
}

func (s *Store) RevokeTokenFamily(_ context.Context, familyID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.families[familyID]
	if !ok {
		return storage.ErrNotFound
	}
	s.revokeFamilyLocked(f, now)
	return nil
}

func (s *Store) revokeFamilyLocked(f *token.Family, now time.Time) {
	if f.Active() {
		f.Status = token.FamilyRevoked
		f.RevokedAt = now
	}
	for _, t := range s.access {
		if t.FamilyID == f.ID && t.Status == token.AccessActive {
			t.Status = token.AccessRevoked
			t.RevokedAt = now
		}
	}
	for _, t := range s.refresh {
		if t.FamilyID == f.ID && t.Status != token.RefreshRevoked {
			t.Status = token.RefreshRevoked
			t.RevokedAt = now
		}
	}
}

func (s *Store) RevokeAccessToken(_ context.Context, hash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.access[hash]
	if !ok {
		return storage.ErrNotFound
	}
	if t.Status == token.AccessActive {
		t.Status = token.AccessRevoked
		t.RevokedAt = now
	}
	return nil
}

// --- Purge ---

func (s *Store) Purge(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.txns {
		if t.Expired(now) {
			delete(s.txns, id)
		}
	}
	for h, c := range s.codes {
		if c.Expired(now) {
			delete(s.codes, h)
		}
	}
	for h, t := range s.access {
		if !now.Before(t.ExpiresAt) {
			delete(s.access, h)
		}
	}
	for h, t := range s.refresh {
		if !now.Before(t.ExpiresAt) {
			delete(s.refresh, h)
		}
	}
	return nil
}
