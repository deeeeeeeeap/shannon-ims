package sim

import (
	"os"
	"syscall"
	"unsafe"
)

// Linux 的 Termios 结构 (syscall.Termios 是平台特定的)
// 我们使用 syscall 包，该包在 Linux 上可用。
// 注意: 这可能不容易交叉编译到 Windows，但用户是在 Linux 上。

func setSerialParam(fd uintptr, baudRate int) error {
	var termios syscall.Termios

	// 获取当前设置
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)), 0, 0, 0); err != 0 {
		return err
	}

	// 设置输入/输出速度
	// syscall 中定义的标准波特率
	var speed uint32
	switch baudRate {
	case 9600:
		speed = syscall.B9600
	case 19200:
		speed = syscall.B19200
	case 38400:
		speed = syscall.B38400
	case 57600:
		speed = syscall.B57600
	case 115200:
		speed = syscall.B115200
	default:
		speed = syscall.B115200
	}

	// 设置原始模式 (8N1, 无回显, 无信号)
	// CFG 标志
	termios.Cflag &^= syscall.PARENB | syscall.CSTOPB | syscall.CSIZE
	termios.Cflag |= syscall.CS8 | syscall.CREAD | syscall.CLOCAL

	// 输入标志 (无流控制, 无软件流控制)
	termios.Iflag &^= syscall.IXON | syscall.IXOFF | syscall.IXANY | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL

	// 本地标志 (无规范模式, 无回显)
	termios.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ECHOE | syscall.ISIG

	// 输出标志 (无处理)
	termios.Oflag &^= syscall.OPOST

	// 设置速度
	termios.Ispeed = speed
	termios.Ospeed = speed

	// VMIN, VTIME
	termios.Cc[syscall.VMIN] = 1
	termios.Cc[syscall.VTIME] = 0

	// 设置属性
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&termios)), 0, 0, 0); err != 0 {
		return err
	}

	return nil
}

func OpenSerial(path string, baudRate int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0666)
	if err != nil {
		return nil, err
	}

	// 清除非阻塞
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil {
		f.Close()
		return nil, err
	}

	if err := setSerialParam(f.Fd(), baudRate); err != nil {
		f.Close()
		return nil, err
	}

	return f, nil
}
