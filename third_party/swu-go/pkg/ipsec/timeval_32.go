//go:build arm || 386 || mips || mipsle || ppc || s390

package ipsec

import "syscall"

func durationToTimeval(sec int64, usec int64) syscall.Timeval {
	return syscall.Timeval{
		Sec:  int32(sec),
		Usec: int32(usec),
	}
}
