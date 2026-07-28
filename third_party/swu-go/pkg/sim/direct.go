package sim

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type DirectSIM struct {
	devPath string
	file    *os.File
	mu      sync.Mutex
}

func NewDirectSIM(path string) (*DirectSIM, error) {
	// 默认波特率 115200
	f, err := OpenSerial(path, 115200)
	if err != nil {
		return nil, err
	}
	return &DirectSIM{
		devPath: path,
		file:    f,
	}, nil
}

func (s *DirectSIM) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// 发送 AT 指令并等待 OK 或 ERROR
func (s *DirectSIM) sendATCommand(cmd string, timeout time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 刷新输入
	// ioutil.ReadAll(s.file) ? 不，可能会阻塞。
	// 尽力而为刷新读取。

	if _, err := s.file.WriteString(cmd + "\r\n"); err != nil {
		return "", err
	}

	// Read loop
	deadLine := time.Now().Add(timeout)
	var response bytes.Buffer
	scanner := bufio.NewScanner(s.file)

	// 手动检查截止日期或使用 channel？
	// 如果不对 os.File 设置 ReadDeadline (Go 1.12+ 可用)，阻塞读取可能会挂起。
	s.file.SetReadDeadline(deadLine)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		response.WriteString(line + "\n")

		if line == "OK" {
			return response.String(), nil
		}
		if strings.Contains(line, "ERROR") {
			return response.String(), fmt.Errorf("AT command error: %s", line)
		}

		if time.Now().After(deadLine) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return response.String(), err
	}

	return response.String(), errors.New("AT command timeout")
}

func (s *DirectSIM) GetIMSI() (string, error) {
	resp, err := s.sendATCommand("AT+CIMI", 2*time.Second)
	if err != nil {
		return "", err
	}

	// Parse IMSI
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		// 有效的 IMSI 通常是 15 位数字
		if len(line) >= 14 && len(line) <= 16 && isDigits(line) {
			return line, nil
		}
	}
	return "", errors.New("IMSI not found in response")
}

func (s *DirectSIM) GetIMEI() (string, error) {
	resp, err := s.sendATCommand("AT+CGSN", 2*time.Second)
	if err != nil {
		resp, err = s.sendATCommand("AT+GSN", 2*time.Second)
		if err != nil {
			return "", err
		}
	}

	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) >= 14 && len(line) <= 17 && isDigits(line) {
			return line, nil
		}
	}
	return "", errors.New("IMEI not found in response")
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *DirectSIM) CalculateAKA(rand, autn []byte) ([]byte, []byte, []byte, []byte, error) {
	// 构造 APDU
	// P2 = 81 (EAP-AKA)
	// Lc = 1 (RandLen) + 16 (Rand) + 1 (AutnLen) + 16 (Autn) = 34
	// Data = 10 + RAND + 10 + AUTN

	payload := fmt.Sprintf("10%X10%X", rand, autn)
	p2 := "81" // Authenticate Context
	p3 := fmt.Sprintf("%02X", len(payload)/2)

	apdu := "008800" + p2 + p3 + payload

	// 发送 AT+CSIM
	cmd := fmt.Sprintf("AT+CSIM=%d,\"%s\"", len(apdu), apdu)
	resp, err := s.sendATCommand(cmd, 3*time.Second)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 解析 +CSIM: <len>,"<hex>"
	// 预期: +CSIM: 4,"61xx" (需要 Get Response) 或 +CSIM: xx,"DB..."

	csimData, err := parseCSIMResponse(resp)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 检查状态字
	if len(csimData) < 2 {
		return nil, nil, nil, nil, errors.New("CSIM response too short")
	}

	sw1 := csimData[len(csimData)-2]
	sw2 := csimData[len(csimData)-1]

	if sw1 == 0x61 {
		// 需要 Get Response。SW2 是长度。
		// 发送 00 C0 00 00 <Len>
		getResponseApdu := fmt.Sprintf("00C00000%02X", sw2)
		cmdGR := fmt.Sprintf("AT+CSIM=%d,\"%s\"", len(getResponseApdu), getResponseApdu)
		respGR, err := s.sendATCommand(cmdGR, 3*time.Second)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		csimData, err = parseCSIMResponse(respGR)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// Get Response 的状态字
		if len(csimData) < 2 {
			return nil, nil, nil, nil, errors.New("Get Response too short")
		}
		sw1 = csimData[len(csimData)-2]
		sw2 = csimData[len(csimData)-1]
	}

	if sw1 != 0x90 || sw2 != 0x00 {
		// 同步失败通常返回 98 62 (认证错误) 和 AUTS？
		// 或者返回带有同步失败的 DB 标签？
		// 在数据中检查同步失败标签 `DC`？
		return nil, nil, nil, nil, fmt.Errorf("CSIM SW Error: %02X %02X", sw1, sw2)
	}

	if len(csimData) >= 4 {
		body := csimData[:len(csimData)-2]
		switch body[0] {
		case 0xDB:
			res, ck, ik, ok := parseUSIMAuthDB(body)
			if ok {
				return res, ck, ik, nil, nil
			}
			data, err := parseTLVData(body)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			res, ck, ik, ok = parseUSIMAuthDB(append([]byte{0xDB}, data...))
			if ok {
				return res, ck, ik, nil, nil
			}
			return nil, nil, nil, nil, errors.New("AKA 成功响应解析失败")
		case 0xDC:
			data, err := parseTLVData(body)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return nil, nil, nil, append([]byte(nil), data...), ErrSyncFailure
		case 0xDD:
			return nil, nil, nil, nil, errors.New("AKA MAC 校验失败")
		}
	}

	// 解码 3G 响应 (标签 DB)
	// 格式: DB <Len> <TLV>...
	if csimData[0] != 0xDB {
		// 检查同步失败
		if csimData[0] == 0xDC {
			// 同步失败，返回 AUTS
			// 格式: DC <Len> <AUTS(14)>
			body, err := parseTagBody(csimData[:len(csimData)-2])
			if err != nil {
				return nil, nil, nil, nil, ErrSyncFailure
			}
			if len(body) >= 14 {
				auts := body[:14]
				return nil, nil, nil, auts, ErrSyncFailure
			}
			return nil, nil, nil, nil, ErrSyncFailure
		}
		return nil, nil, nil, nil, fmt.Errorf("Unknown CSIM Tag: %02X", csimData[0])
	}

	dataNoSW := csimData[:len(csimData)-2]
	var dataBody []byte
	if len(dataNoSW) >= 2 && dataNoSW[1] <= 0x20 && len(dataNoSW) > 2+int(dataNoSW[1]) {
		dataBody = dataNoSW[1:]
	} else {
		dataBody, err = parseTagBody(dataNoSW)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	for i := 0; i < 4; i++ {
		inner, ok := unwrapConstructedTLV(dataBody)
		if !ok {
			break
		}
		dataBody = inner
	}

	// TLV 解析
	var res, ck, ik []byte

	idx := 0
	for idx < len(dataBody) {
		tag := dataBody[idx]
		idx++
		if idx >= len(dataBody) {
			break
		}
		length := int(dataBody[idx])
		idx++

		if idx+length > len(dataBody) {
			break
		}
		val := dataBody[idx : idx+length]
		idx += length

		switch tag {
		case 0x80: // RES
			res = val
		case 0x81: // CK
			ck = val
		case 0x82: // IK
			ik = val
		}

		// 回退: 如果标签是任意的但顺序固定: RES -> CK -> IK
		// 让我们收集它们
	}

	if len(res) > 0 && len(ck) > 0 && len(ik) > 0 {
		return res, ck, ik, nil, nil
	}

	// 快速处理: 按照固定偏移量/标准结构解析如果 TLV 失败?
	// 让我们重读 TS 31.102 7.1.2.
	// "响应参数/数据: 在 AUTHENTICATE 的情况下... : RES, CK, IK, Kc"
	// "响应数据使用 GET RESPONSE 检索。"
	// "响应数据的内容 ... (成功):"
	// 字节 1: 'DB'
	// 字节 2: 长度
	// 字节 3: RES 长度 (L1)
	// 字节 4..4+L1-1: RES
	// 字节 4+L1: CK 长度 (L2)
	// ... CK
	// ... IK 长度 (L3)
	// ... IK
	// ...
	// 所以是 LV, LV, LV. 不是 TLV.

	off := 0
	if off >= len(dataBody) {
		return nil, nil, nil, nil, errors.New("Empty data")
	}

	lRes := int(dataBody[off])
	off++
	if off+lRes > len(dataBody) {
		return nil, nil, nil, nil, fmt.Errorf("Invalid RES length lRes=%d bodyLen=%d first=0x%02X", lRes, len(dataBody), dataBody[0])
	}
	res = dataBody[off : off+lRes]
	off += lRes

	if off >= len(dataBody) {
		return nil, nil, nil, nil, errors.New("Missing CK length")
	}
	lCk := int(dataBody[off])
	off++
	if off+lCk > len(dataBody) {
		return nil, nil, nil, nil, fmt.Errorf("Invalid CK length lCk=%d bodyLen=%d", lCk, len(dataBody))
	}
	ck = dataBody[off : off+lCk]
	off += lCk

	if off >= len(dataBody) {
		return nil, nil, nil, nil, errors.New("Missing IK length")
	}
	lIk := int(dataBody[off])
	off++
	if off+lIk > len(dataBody) {
		return nil, nil, nil, nil, fmt.Errorf("Invalid IK length lIk=%d bodyLen=%d", lIk, len(dataBody))
	}
	ik = dataBody[off : off+lIk]

	return res, ck, ik, nil, nil
}

func parseTagBody(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("tag data too short")
	}
	if len(data) < 2 {
		return nil, errors.New("tag data too short")
	}
	lb := data[1]
	if lb <= 0x7f {
		l := int(lb)
		if 2+l > len(data) {
			return nil, errors.New("tag length out of range")
		}
		return data[2 : 2+l], nil
	}
	if lb == 0x81 {
		if len(data) < 3 {
			return nil, errors.New("tag length too short")
		}
		l := int(data[2])
		if 3+l > len(data) {
			return nil, errors.New("tag length out of range")
		}
		return data[3 : 3+l], nil
	}
	if lb == 0x82 {
		if len(data) < 4 {
			return nil, errors.New("tag length too short")
		}
		l := int(data[2])<<8 | int(data[3])
		if 4+l > len(data) {
			return nil, errors.New("tag length out of range")
		}
		return data[4 : 4+l], nil
	}
	return nil, errors.New("unsupported tag length encoding")
}

func unwrapConstructedTLV(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	tag := data[0]
	if tag&0x20 == 0 {
		return nil, false
	}
	l, lLen, ok := parseBERLength(data[1:])
	if !ok {
		return nil, false
	}
	start := 1 + lLen
	if start+l > len(data) {
		return nil, false
	}
	return data[start : start+l], true
}

func parseBERLength(data []byte) (length int, lengthLen int, ok bool) {
	if len(data) < 1 {
		return 0, 0, false
	}
	b := data[0]
	if b <= 0x7f {
		return int(b), 1, true
	}
	if b == 0x81 {
		if len(data) < 2 {
			return 0, 0, false
		}
		return int(data[1]), 2, true
	}
	if b == 0x82 {
		if len(data) < 3 {
			return 0, 0, false
		}
		return int(data[1])<<8 | int(data[2]), 3, true
	}
	return 0, 0, false
}

func parseCSIMResponse(resp string) ([]byte, error) {
	// lines: ...\n+CSIM: x,"DEAD..."\n...OK
	start := strings.Index(resp, "+CSIM:")
	if start == -1 {
		return nil, errors.New("Not a CSIM response")
	}

	// find first quote
	q1 := strings.Index(resp[start:], "\"")
	if q1 == -1 {
		return nil, errors.New("Parse error quote")
	}
	q1 += start

	q2 := strings.Index(resp[q1+1:], "\"")
	if q2 == -1 {
		return nil, errors.New("Parse error quote 2")
	}
	q2 += q1 + 1

	hexStr := resp[q1+1 : q2]
	return hex.DecodeString(hexStr)
}

func parseTLVData(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, errors.New("响应体过短")
	}
	l := int(body[1])
	if len(body) < 2+l {
		return nil, fmt.Errorf("响应体长度不匹配: need=%d have=%d", 2+l, len(body))
	}
	return body[2 : 2+l], nil
}

func parseUSIMAuthDB(body []byte) (res, ck, ik []byte, ok bool) {
	if len(body) < 2 || body[0] != 0xDB {
		return nil, nil, nil, false
	}
	pos := 1
	resLen := int(body[pos])
	pos++
	if resLen <= 0 || len(body) < pos+resLen {
		return nil, nil, nil, false
	}
	res = append([]byte(nil), body[pos:pos+resLen]...)
	pos += resLen

	remain := len(body) - pos
	if remain == 32 {
		ck = append([]byte(nil), body[pos:pos+16]...)
		ik = append([]byte(nil), body[pos+16:pos+32]...)
		return res, ck, ik, true
	}

	if remain < 2 {
		return nil, nil, nil, false
	}
	ckLen := int(body[pos])
	pos++
	if ckLen <= 0 || len(body) < pos+ckLen+1 {
		return nil, nil, nil, false
	}
	ck = append([]byte(nil), body[pos:pos+ckLen]...)
	pos += ckLen

	ikLen := int(body[pos])
	pos++
	if ikLen <= 0 || len(body) < pos+ikLen {
		return nil, nil, nil, false
	}
	ik = append([]byte(nil), body[pos:pos+ikLen]...)
	return res, ck, ik, true
}
