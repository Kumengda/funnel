package funnel

import "github.com/google/gopacket"

type Source struct {
	*Funnel
	name   string
	source *gopacket.PacketSource
}

func NewSource(name string, f *Funnel, source *gopacket.PacketSource) *Source {
	return &Source{name: name, Funnel: f, source: source}
}

func (s *Source) Packets() chan gopacket.Packet {
	return s.source.Packets()
}

func (s *Source) Monitor(m Monitor) {
	s.status.Store(s.name, CONTINUE)
	go func() {
		for p := range s.source.Packets() {
			sign := m.Inspector(p)
			switch sign {
			case CONTINUE:
				continue
			case TERMINATE:
				s.status.Store(s.name, TERMINATE)
				return
			}
		}
	}()
}
