package policyengine

import "sync"

// ─── JA4 Registry ───────────────────────────────────────────────────
//
// Package-level sync.Map mapping TCP remote addresses ("ip:port") to
// their computed JA4 fingerprint. Written by the listener wrapper on
// Accept(), read by the policy engine in ServeHTTP(), deleted on
// connection Close().

var ja4Registry ja4Store

type ja4Store struct {
	m sync.Map
}

func (s *ja4Store) Set(addr, ja4 string) { s.m.Store(addr, ja4) }

func (s *ja4Store) Get(addr string) string {
	v, ok := s.m.Load(addr)
	if !ok {
		return ""
	}
	return v.(string)
}

func (s *ja4Store) Delete(addr string) { s.m.Delete(addr) }
