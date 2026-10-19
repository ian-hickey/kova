//go:build !(darwin || linux || freebsd || netbsd || openbsd)

package lockfile

import "os"

// Windows and anything else: size and mtime only (no inode or ctime available portably).
func sigOf(st os.FileInfo) statSig {
	return statSig{Size: st.Size(), Mtime: st.ModTime().UnixNano()}
}
