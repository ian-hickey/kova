package mcp

import (
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// NetSnapshot lists the remote endpoints ("host:port") a process tree currently has open.
// Best effort: uses pgrep/lsof on macOS and Linux and returns nil anywhere else or on error.
// This is a heuristic, not a firewall; see README "What the network check can and cannot see".
func NetSnapshot(pid int) map[string]bool {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil
	}
	pids := descendants(pid)
	pids = append(pids, pid)
	strs := make([]string, len(pids))
	for i, p := range pids {
		strs[i] = strconv.Itoa(p)
	}
	out, err := exec.Command("lsof", "-a", "-p", strings.Join(strs, ","), "-i", "-n", "-P", "-F", "n").Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "n") {
			continue
		}
		name := line[1:]
		if i := strings.Index(name, "->"); i >= 0 {
			set[name[i+2:]] = true
		}
	}
	return set
}

func descendants(pid int) []int {
	var out []int
	queue := []int{pid}
	for len(queue) > 0 && len(out) < 64 {
		p := queue[0]
		queue = queue[1:]
		raw, err := exec.Command("pgrep", "-P", strconv.Itoa(p)).Output()
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(raw)) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, n)
				queue = append(queue, n)
			}
		}
	}
	return out
}

// NewDestinations returns endpoints present in after but not before, sorted.
func NewDestinations(before, after map[string]bool) []string {
	var out []string
	for k := range after {
		if !before[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
