package funnel

import "github.com/google/gopacket"

type MonitorSign string

const (
	TERMINATE MonitorSign = "TERMINATE"
	CONTINUE  MonitorSign = "CONTINUE"
	INIT      MonitorSign = "INIT"
)

type Monitor interface {
	Inspector(p gopacket.Packet) MonitorSign
}

type BasicMonitor struct {
	inspector func(p gopacket.Packet) MonitorSign
}

func NewBaseMonitor(inspector func(p gopacket.Packet) MonitorSign) *BasicMonitor {
	return &BasicMonitor{inspector: inspector}
}
func (m *BasicMonitor) Inspector(p gopacket.Packet) MonitorSign {
	return m.inspector(p)
}
