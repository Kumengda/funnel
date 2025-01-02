package funnel

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Funnel struct {
	handles map[string]*pcap.Handle
}

func NewFunnel() *Funnel {
	initDecoration()
	return &Funnel{handles: make(map[string]*pcap.Handle)}
}

func EnableDebug() {
	Log.SetVisible(true)
}

func (f *Funnel) SetHandles(des []HandleDes) error {
	err := checkDeviceName(des)
	if err != nil {
		return err
	}
	for _, d := range des {
		handle, err := pcap.OpenLive(d.DeviceName, 1600, d.Promisc, d.Timeout)
		if err != nil {
			return errors.New("Failed to open device " + d.DeviceName + ": " + err.Error())
		}
		if _, ok := f.handles[d.Name]; ok {
			return errors.New("Device " + d.Name + " already exists")
		}
		err = handle.SetBPFFilter(d.Bpfilter)
		if err != nil {
			return errors.New("Failed to set BPF filter: " + err.Error())
		}
		f.handles[d.Name] = handle
	}
	return nil
}

func (f *Funnel) GetPackageSource(name string) (*gopacket.PacketSource, error) {
	if _, ok := f.handles[name]; ok {
		handle := f.handles[name]
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		return packetSource, nil
	}
	return nil, errors.New("Handle " + name + " not found")
}

func (f *Funnel) CloseHandle(name ...string) {
	for _, n := range name {
		f.handles[n].Close()
	}
}
func (f *Funnel) CloseAllHandle() {
	for _, h := range f.handles {
		h.Close()
	}
}
