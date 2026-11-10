package modem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vohive/pkg/smscodec"
)

// IncomingSMSSink 接管一条从模组短信存储中读出的已接收短信。
// tpdu 是去掉短信中心地址之后的 SMS-DELIVER 传输层 PDU。
//
// 返回值决定模组里那份副本的去留：
//   - nil：短信已经安全（已入库、是重复项，或被有意丢弃），副本可以删除；
//   - ErrIncomingSMSNotTaken：接收方不处理这一条，由 Manager 按原有方式自行解码并
//     通过短信回调上报，随后删除副本；
//   - 其他错误：副本留在模组里，下一次 DrainStoredSMS 会再次交给接收方。
type IncomingSMSSink func(tpdu []byte) error

// ErrIncomingSMSNotTaken 由 IncomingSMSSink 返回，表示这一条交还给 Manager 自行处理。
var ErrIncomingSMSNotTaken = errors.New("短信未被接收流水线接管")

// SetIncomingSMSSink 设置已接收短信的接收方；传入 nil 表示取消。
func (m *Manager) SetIncomingSMSSink(sink IncomingSMSSink) {
	m.infoMu.Lock()
	m.incomingSMSSink = sink
	m.infoMu.Unlock()
}

// 短信在存储中的状态（3GPP TS 27.005，PDU 模式下的 <stat>）。
const (
	smsStatusReceivedUnread = 0
	smsStatusReceivedRead   = 1
)

// StoredSMS 是模组当前短信存储中的一条记录。
type StoredSMS struct {
	Index  int    // 在存储中的位置，即 AT+CMGR / AT+CMGD 使用的索引
	Status int    // 0 已接收未读，1 已接收已读，2 已存储未发送，3 已存储已发送
	PDUHex string // 含短信中心地址的完整 PDU，十六进制
}

// Received 报告这条记录是否为从网络收到的短信。
func (s StoredSMS) Received() bool {
	return s.Status == smsStatusReceivedUnread || s.Status == smsStatusReceivedRead
}

// parseCMGLEntries 解析 PDU 模式下 AT+CMGL 的应答：
//
//	+CMGL: <index>,<stat>,[<alpha>],<length>
//	<pdu>
//
// 无法识别索引、状态或缺少 PDU 行的条目会被跳过：没有索引就无法安全地删除它。
func parseCMGLEntries(resp string) []StoredSMS {
	lines := splitLines(resp)
	entries := make([]StoredSMS, 0, len(lines)/2)
	for i := 0; i < len(lines); i++ {
		header := lines[i]
		if !strings.HasPrefix(header, "+CMGL:") {
			continue
		}
		fields := parseCommaFields(parseURCAfterColon(header))
		if len(fields) < 2 || i+1 >= len(lines) {
			continue
		}
		next := lines[i+1]
		if next == "" || next == "OK" || strings.HasPrefix(next, "+CMGL:") {
			continue
		}
		i++

		indexText, ok := normalizeSMSIndex(fields[0])
		if !ok {
			continue
		}
		index, err := strconv.Atoi(indexText)
		if err != nil {
			continue
		}
		status, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		pduHex, _ := smscodec.TrimFullPDUHexByATHeader(next, header)
		entries = append(entries, StoredSMS{Index: index, Status: status, PDUHex: pduHex})
	}
	return entries
}

// smsStorageUsage 是 AT+CPMS? 应答中的一个存储。
type smsStorageUsage struct {
	name      string
	used      int
	usedKnown bool
}

// parseCPMSUsage 解析 AT+CPMS? 的应答，依次返回 mem1（读取与删除）、mem2（写入与发送）、
// mem3（新收短信的存放处）：
//
//	+CPMS: <mem1>,<used1>,<total1>,<mem2>,<used2>,<total2>,<mem3>,<used3>,<total3>
//
// 只有三个存储都能识别时才返回结果，否则返回 nil。
func parseCPMSUsage(resp string) []smsStorageUsage {
	line, ok := findLineWithPrefix(resp, "+CPMS:")
	if !ok {
		return nil
	}
	fields := parseCommaFields(parseURCAfterColon(line))
	if len(fields) < 7 {
		return nil
	}
	memories := make([]smsStorageUsage, 0, 3)
	for i := 0; i < len(fields) && len(memories) < 3; i += 3 {
		name, ok := normalizeSMSStorage(fields[i])
		if !ok {
			return nil
		}
		usage := smsStorageUsage{name: name}
		if i+1 < len(fields) {
			if used, err := strconv.Atoi(fields[i+1]); err == nil && used >= 0 {
				usage.used, usage.usedKnown = used, true
			}
		}
		memories = append(memories, usage)
	}
	if len(memories) != 3 {
		return nil
	}
	return memories
}

// ListStoredSMS 列出当前短信存储中的全部记录（AT+CMGL=4），带真实的存储索引。
func (m *Manager) ListStoredSMS() ([]StoredSMS, error) {
	resp, err := m.ExecuteAT("AT+CMGL=4", 10*time.Second)
	if err != nil {
		// AT+CMGL=4 只在 PDU 模式下有效：重新选择 PDU 模式后再试一次。
		if _, modeErr := m.ExecuteAT("AT+CMGF=0", 3*time.Second); modeErr != nil {
			return nil, err
		}
		if resp, err = m.ExecuteAT("AT+CMGL=4", 10*time.Second); err != nil {
			return nil, err
		}
	}
	return parseCMGLEntries(resp), nil
}

// DrainStoredSMS 补收仍留在模组短信存储里的已接收短信：逐条交给接收流程，
// 只删除已经被接收流程接下的那些，并按存储中的真实索引删除。
//
// 新短信提示（+CMTI）可能在程序未运行、串口重连或模组忙时丢失，读取或入库也可能
// 失败；这些短信都还在存储里，由本方法收回。它处理 mem1 与 mem3 两个存储，
// 计数为零的存储不会被读取。模组忙（正在发送短信等）时直接返回，等下一次。
//
// handled 是本次从模组中删除的短信数。
func (m *Manager) DrainStoredSMS() (handled int, err error) {
	if m.IsBusy() {
		return 0, nil
	}

	m.smsInboxMu.Lock()
	defer m.smsInboxMu.Unlock()

	resp, err := m.ExecuteAT("AT+CPMS?", 3*time.Second)
	if err != nil {
		return 0, fmt.Errorf("查询短信存储失败: %w", err)
	}
	memories := parseCPMSUsage(resp)
	if memories == nil {
		// 识别不出存储布局：只处理当前存储，不做切换。
		return m.drainCurrentSMSStorage()
	}

	current := memories[0].name
	targets := []smsStorageUsage{memories[0]}
	if memories[2].name != current {
		targets = append(targets, memories[2])
	}
	restoreCmd := cpmsSetCommand(memories[0].name, memories[1].name, memories[2].name)

	for _, target := range targets {
		if target.usedKnown && target.used == 0 {
			continue
		}
		switched := false
		if target.name != current {
			if _, switchErr := m.ExecuteAT(cpmsSetCommand(target.name), 5*time.Second); switchErr != nil {
				if err == nil {
					err = fmt.Errorf("切换短信存储 %s 失败: %w", target.name, switchErr)
				}
				continue
			}
			switched = true
		}

		count, drainErr := m.drainCurrentSMSStorage()
		handled += count
		if drainErr != nil && err == nil {
			err = drainErr
		}

		if switched {
			if _, restoreErr := m.ExecuteAT(restoreCmd, 5*time.Second); restoreErr != nil {
				logger.Warn(fmt.Sprintf("[%s] 恢复短信存储失败", m.cfg.ID), "storage", current, "err", restoreErr)
			}
		}
	}
	return handled, err
}

// drainCurrentSMSStorage 处理当前存储中的已接收短信。调用方持有 smsInboxMu。
func (m *Manager) drainCurrentSMSStorage() (int, error) {
	entries, err := m.ListStoredSMS()
	if err != nil {
		return 0, fmt.Errorf("列举短信失败: %w", err)
	}

	handled := 0
	for _, entry := range entries {
		if !entry.Received() {
			// 存储里的草稿或已发送短信不属于接收流程，保持原样。
			continue
		}
		if !m.deliverStoredSMS(entry.PDUHex) {
			continue
		}
		if _, err := m.ExecuteAT(fmt.Sprintf("AT+CMGD=%d", entry.Index), 3*time.Second); err != nil {
			logger.Warn(fmt.Sprintf("[%s] 删除已处理短信失败，下次补收时重试", m.cfg.ID), "index", entry.Index, "err", err)
			continue
		}
		handled++
	}
	if handled > 0 {
		logger.Info(fmt.Sprintf("[%s] 补收模组存储中的短信", m.cfg.ID), "handled", handled, "listed", len(entries))
	}
	return handled, nil
}

// deliverStoredSMS 把一条从存储中读出的短信（模组返回的 PDU 十六进制串）交给接收流程，
// 并报告模组里的副本是否可以删除。调用方持有 smsInboxMu。
func (m *Manager) deliverStoredSMS(pduHex string) bool {
	m.infoMu.RLock()
	sink := m.incomingSMSSink
	callback := m.smsCallback
	m.infoMu.RUnlock()

	key := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(pduHex))))
	if m.presentedSMS.contains(key) {
		// 这条已经由原有路径处理过，只是上次没删掉：不再交给接收流水线，也不重复上报，只重试删除。
		return true
	}

	if sink != nil {
		if tpdu, ok := storedSMSTPDU(pduHex); ok {
			err := sink(tpdu)
			if err == nil {
				return true
			}
			if !errors.Is(err, ErrIncomingSMSNotTaken) {
				logger.Warn(fmt.Sprintf("[%s] 短信暂未入库，保留在模组中等待下次补收", m.cfg.ID),
					"pdu_len", len(tpdu), "err", err)
				return false
			}
		}
	}

	// 原有路径：自行解码，长短信在内存中重组，完整后通过回调上报。
	m.presentedSMS.add(key)

	sender, content, timestamp := m.decodePDU(pduHex)
	if content == "" {
		// 长短信的分片尚未凑齐：分片已保存在内存中，存储里的副本可以删除，否则存储会被占满。
		return true
	}

	logger.Debug(fmt.Sprintf("[%s] 短信已解码", m.cfg.ID),
		"sender_len", len(sender),
		"sender_fingerprint", logger.Fingerprint(sender),
		"content_len", len(content),
		"content_fingerprint", logger.Fingerprint(content))

	if callback != nil {
		callback(sender, content, timestamp)
	}
	return true
}

// storedSMSTPDU 从模组返回的 PDU 十六进制串中取出传输层 PDU。
func storedSMSTPDU(pduHex string) ([]byte, bool) {
	raw, err := hex.DecodeString(strings.TrimSpace(pduHex))
	if err != nil {
		return nil, false
	}
	tpdu, err := smscodec.TPDUFromPDU(raw)
	if err != nil {
		return nil, false
	}
	return tpdu, true
}

const presentedSMSCapacity = 256

// presentedSMSSet 记住最近由 Manager 自行解码并上报过的短信（按 PDU 的摘要）。
//
// 删除失败的短信会在下一次补收时被再次读到，不能因此重复上报。容量固定，
// 满了以后覆盖最早的记录。
type presentedSMSSet struct {
	ring  [presentedSMSCapacity][sha256.Size]byte
	used  int
	next  int
	known map[[sha256.Size]byte]struct{}
}

func (s *presentedSMSSet) contains(key [sha256.Size]byte) bool {
	_, ok := s.known[key]
	return ok
}

func (s *presentedSMSSet) add(key [sha256.Size]byte) {
	if s.known == nil {
		s.known = make(map[[sha256.Size]byte]struct{}, presentedSMSCapacity)
	}
	if _, ok := s.known[key]; ok {
		return
	}
	if s.used == presentedSMSCapacity {
		delete(s.known, s.ring[s.next])
	} else {
		s.used++
	}
	s.ring[s.next] = key
	s.next = (s.next + 1) % presentedSMSCapacity
	s.known[key] = struct{}{}
}
