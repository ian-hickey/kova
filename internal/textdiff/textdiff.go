// Package textdiff produces small unified diffs of instruction files so that `kova verify` can show
// a human WHAT changed in a CLAUDE.md (not just two hash prefixes) and so the optional triage stage
// can judge the edit rather than the whole file. It is deliberately simple: an LCS over lines with
// size caps, since the files involved are a few kilobytes.
package textdiff

import (
	"fmt"
	"strings"
)

// Limits keep the diff bounded for hook output and event payloads.
const (
	maxLines    = 4000 // per side; bigger inputs get a one-line summary instead of a diff
	defaultCtx  = 3
	MaxBytes    = 6 << 10 // callers should truncate with Truncate before shipping a diff anywhere
	elidedLabel = "… diff truncated …"
)

// Unified returns a unified diff between a and b labelled with name. Empty when identical.
func Unified(name, a, b string) string {
	if a == b {
		return ""
	}
	al, bl := splitLines(a), splitLines(b)
	if len(al) > maxLines || len(bl) > maxLines {
		return fmt.Sprintf("--- %s (pinned, %d lines)\n+++ %s (now, %d lines)\n@@ file too large to diff @@\n", name, len(al), name, len(bl))
	}
	ops := diffOps(al, bl)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s (pinned)\n+++ %s (now)\n", name, name)
	// Group ops into hunks with context.
	type hunk struct{ start, end int } // indices into ops
	var hunks []hunk
	last := -1
	for i, op := range ops {
		if op.kind == ' ' {
			continue
		}
		if last >= 0 && i-hunks[last].end <= 2*defaultCtx {
			hunks[last].end = i
		} else {
			hunks = append(hunks, hunk{i, i})
			last++
		}
	}
	for _, h := range hunks {
		s, e := h.start-defaultCtx, h.end+defaultCtx
		if s < 0 {
			s = 0
		}
		if e > len(ops)-1 {
			e = len(ops) - 1
		}
		aStart, bStart, aN, bN := 0, 0, 0, 0
		for i := 0; i < s; i++ {
			switch ops[i].kind {
			case ' ':
				aStart++
				bStart++
			case '-':
				aStart++
			case '+':
				bStart++
			}
		}
		for i := s; i <= e; i++ {
			switch ops[i].kind {
			case ' ':
				aN++
				bN++
			case '-':
				aN++
			case '+':
				bN++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aStart+1, aN, bStart+1, bN)
		for i := s; i <= e; i++ {
			sb.WriteByte(byte(ops[i].kind))
			sb.WriteString(ops[i].text)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// Truncate cuts a diff to at most n bytes on a line boundary, marking the cut.
func Truncate(d string, n int) string {
	if len(d) <= n {
		return d
	}
	cut := strings.LastIndexByte(d[:n], '\n')
	if cut <= 0 {
		cut = n
	}
	return d[:cut] + "\n" + elidedLabel + "\n"
}

// AddedLines returns only the '+' lines of a unified diff (without the marker), which is what a
// reviewer or a classifier mostly needs when a file grew.
func AddedLines(d string) []string {
	var out []string
	for _, l := range strings.Split(d, "\n") {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			out = append(out, l[1:])
		}
	}
	return out
}

type op struct {
	kind rune // ' ', '-', '+'
	text string
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// diffOps is a classic LCS edit script (O(n*m) memory, fine under maxLines for the files we see;
// 4000x4000 ints is 64 MB worst case, which only happens for pathological inputs, so cap tighter
// when both sides are large).
func diffOps(a, b []string) []op {
	n, m := len(a), len(b)
	if n*m > 2_500_000 {
		// Too big for the table: emit a whole-file replace so the caller still sees content.
		var out []op
		for _, l := range a {
			out = append(out, op{'-', l})
		}
		for _, l := range b {
			out = append(out, op{'+', l})
		}
		return out
	}
	// Trim common prefix/suffix first; most instruction-file edits are local.
	pre := 0
	for pre < n && pre < m && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < n-pre && suf < m-pre && a[n-1-suf] == b[m-1-suf] {
		suf++
	}
	core := lcsOps(a[pre:n-suf], b[pre:m-suf])
	out := make([]op, 0, pre+len(core)+suf)
	for _, l := range a[:pre] {
		out = append(out, op{' ', l})
	}
	out = append(out, core...)
	for _, l := range a[n-suf:] {
		out = append(out, op{' ', l})
	}
	return out
}

func lcsOps(a, b []string) []op {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil
	}
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, op{' ', a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, op{'-', a[i]})
			i++
		default:
			out = append(out, op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, op{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, op{'+', b[j]})
	}
	return out
}
