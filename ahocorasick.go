package policyengine

// Aho-Corasick automaton for case-insensitive multi-pattern substring matching.
//
// Used by the phrase_match operator to scan input against wordlists (SQL keywords,
// XSS vectors, command names, etc.) in O(n) time regardless of pattern count.
// Matching is case-insensitive to match CRS/Coraza @pm operator semantics.
//
// This is a minimal, zero-dependency implementation. It builds a trie from the
// pattern set, computes failure links (BFS), and scans input with a single pass.
// Returns the first matched pattern for observability; callers needing only a
// boolean can ignore the matched value.

// toLowerASCII lowercases an ASCII byte without allocation.
// Non-ASCII bytes are returned unchanged.
func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// acNode is a node in the Aho-Corasick trie.
type acNode struct {
	children map[byte]*acNode
	fail     *acNode // failure link — longest proper suffix that is also a prefix
	output   string  // non-empty if this node is the end of a pattern
	hasOut   bool    // true if output is set (distinguishes "" pattern from no match)
	dictFail *acNode // dictionary suffix link — next node in fail chain with output
}

// ACMatcher is a compiled Aho-Corasick automaton for substring matching.
type ACMatcher struct {
	root  *acNode
	empty bool // true if compiled with zero patterns
}

// CompileAC builds an Aho-Corasick automaton from a set of patterns.
// Empty patterns are skipped. Duplicate patterns are harmless (last one wins).
// The returned matcher is safe for concurrent use (read-only after compilation).
func CompileAC(patterns []string) *ACMatcher {
	root := &acNode{children: make(map[byte]*acNode)}
	m := &ACMatcher{root: root}

	// Phase 1: Build trie (goto function).
	// Patterns are lowercased for case-insensitive matching (CRS @pm semantics).
	count := 0
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		count++
		cur := root
		for i := 0; i < len(pat); i++ {
			b := toLowerASCII(pat[i])
			next, ok := cur.children[b]
			if !ok {
				next = &acNode{children: make(map[byte]*acNode)}
				cur.children[b] = next
			}
			cur = next
		}
		cur.output = pat // store original case for logging
		cur.hasOut = true
	}

	if count == 0 {
		m.empty = true
		return m
	}

	// Phase 2: Build failure links (BFS from root's children).
	// Root's children all have fail → root.
	queue := make([]*acNode, 0, len(root.children))
	for _, child := range root.children {
		child.fail = root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for b, child := range cur.children {
			queue = append(queue, child)

			// Walk up fail links to find the longest proper suffix match.
			f := cur.fail
			for f != nil && f.children[b] == nil {
				f = f.fail
			}
			if f == nil {
				child.fail = root
			} else {
				child.fail = f.children[b]
			}
			// Safety: don't let a node's fail link point to itself.
			if child.fail == child {
				child.fail = root
			}

			// Dictionary suffix link: nearest ancestor (via fail chain) with output.
			if child.fail.hasOut {
				child.dictFail = child.fail
			} else {
				child.dictFail = child.fail.dictFail
			}
		}
	}

	return m
}

// ContainsAny returns true if the input contains any pattern as a substring.
// Matching is case-insensitive. This is the primary hot-path method — returns
// as soon as the first match is found.
func (m *ACMatcher) ContainsAny(input string) bool {
	if m.empty {
		return false
	}

	cur := m.root
	for i := 0; i < len(input); i++ {
		b := toLowerASCII(input[i])

		// Follow fail links until we find a transition or reach root.
		for cur != m.root && cur.children[b] == nil {
			cur = cur.fail
		}
		if next, ok := cur.children[b]; ok {
			cur = next
		}

		// Check current node and dictionary suffix chain for matches.
		if cur.hasOut {
			return true
		}
		if cur.dictFail != nil {
			return true
		}
	}
	return false
}

// FindFirst returns the first pattern found as a substring in input, or ("", false)
// if no pattern matches. Matching is case-insensitive. The returned pattern string
// preserves the original case from compilation for logging purposes.
func (m *ACMatcher) FindFirst(input string) (string, bool) {
	if m.empty {
		return "", false
	}

	cur := m.root
	for i := 0; i < len(input); i++ {
		b := toLowerASCII(input[i])

		for cur != m.root && cur.children[b] == nil {
			cur = cur.fail
		}
		if next, ok := cur.children[b]; ok {
			cur = next
		}

		if cur.hasOut {
			return cur.output, true
		}
		if cur.dictFail != nil {
			return cur.dictFail.output, true
		}
	}
	return "", false
}
