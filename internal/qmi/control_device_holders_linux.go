package qmicore

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type qmiControlDeviceHolder struct {
	PID     int
	Command string
}

type qmiControlDeviceHolders struct {
	Holders []qmiControlDeviceHolder
	Unknown bool
}

func (h qmiControlDeviceHolders) onlyQMIProxy() bool {
	if len(h.Holders) == 0 {
		return false
	}
	for _, holder := range h.Holders {
		cmd := strings.ToLower(strings.TrimSpace(holder.Command))
		if !strings.Contains(cmd, "qmi-proxy") {
			return false
		}
	}
	return true
}

var detectQMIControlDeviceHolders = detectQMIControlDeviceHoldersLinux

func detectQMIControlDeviceHoldersLinux(controlDevice string) (qmiControlDeviceHolders, error) {
	controlDevice = strings.TrimSpace(controlDevice)
	if controlDevice == "" {
		return qmiControlDeviceHolders{}, nil
	}

	targetInfo, err := os.Stat(controlDevice)
	if err != nil {
		return qmiControlDeviceHolders{}, err
	}
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return qmiControlDeviceHolders{Unknown: true}, nil
	}

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return qmiControlDeviceHolders{Unknown: true}, err
	}

	out := qmiControlDeviceHolders{}
	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}
		matched, unknown := processHoldsControlDevice(pid, targetStat.Rdev)
		if unknown {
			out.Unknown = true
		}
		if matched {
			out.Holders = append(out.Holders, qmiControlDeviceHolder{
				PID:     pid,
				Command: readProcessCommand(pid),
			})
		}
	}

	sort.Slice(out.Holders, func(i, j int) bool {
		return out.Holders[i].PID < out.Holders[j].PID
	})
	return out, nil
}

func processHoldsControlDevice(pid int, targetRDev uint64) (matched bool, unknown bool) {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false, os.IsPermission(err)
	}
	for _, fd := range fds {
		info, err := os.Stat(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			if os.IsPermission(err) {
				unknown = true
			}
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if st.Rdev == targetRDev && st.Mode&syscall.S_IFMT == syscall.S_IFCHR {
			return true, unknown
		}
	}
	return false, unknown
}

func readProcessCommand(pid int) string {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	if data, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		cmd := strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
		if cmd != "" {
			return cmd
		}
	}
	if data, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}
