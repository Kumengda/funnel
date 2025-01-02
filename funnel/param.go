package funnel

import "time"

type HandleDes struct {
	Name       string
	Bpfilter   string
	DeviceName string
	Promisc    bool
	Timeout    time.Duration
}
