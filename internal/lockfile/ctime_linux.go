//go:build linux

package lockfile

import "syscall"

func ctimeNano(s *syscall.Stat_t) int64 { return s.Ctim.Sec*1e9 + s.Ctim.Nsec }
