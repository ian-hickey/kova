//go:build darwin || linux || freebsd || netbsd || openbsd

package lockfile

import (
	"os"
	"syscall"
)

func sigOf(st os.FileInfo) statSig {
	sig := statSig{Size: st.Size(), Mtime: st.ModTime().UnixNano()}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		sig.Ino = uint64(s.Ino)
		sig.Ctime = ctimeNano(s)
	}
	return sig
}
