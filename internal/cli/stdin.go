package cli

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

// readStdinIfPiped reads all of stdin when it is not a terminal; returns nil otherwise.
func readStdinIfPiped(r io.Reader) []byte {
	if f, ok := r.(*os.File); ok {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeCharDevice != 0 {
			return nil
		}
	}
	type res struct{ b []byte }
	ch := make(chan res, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(r, 8<<20))
		ch <- res{b}
	}()
	select {
	case r := <-ch:
		return r.b
	case <-time.After(2 * time.Second):
		return nil
	}
}

func parseHookCWD(data []byte) string {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	if s, ok := m["cwd"].(string); ok {
		return s
	}
	if roots, ok := m["workspace_roots"].([]any); ok && len(roots) > 0 {
		s, _ := roots[0].(string)
		return s
	}
	return ""
}
