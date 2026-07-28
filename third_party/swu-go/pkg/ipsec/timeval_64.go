//go:build amd64 || arm64 || mips64 || mips64le || ppc64 || ppc64le || s390x || riscv64

package ipsec

import "syscall"

func durationToTimeval(sec int64, usec int64) syscall.Timeval {
	return syscall.Timeval{
		Sec:  sec,
		Usec: usec,
	}
}
