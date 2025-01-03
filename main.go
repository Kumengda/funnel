package main

import (
	"bytes"
	"fmt"
	"github.com/Kumengda/funnel/funnel"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	funn := funnel.NewFunnel()
	err := funn.SetHandles([]funnel.HandleDes{{
		Name:       "TcpFilter_Wifi",
		Bpfilter:   "tcp",
		DeviceName: "en0",
		Promisc:    true,
		Timeout:    pcap.BlockForever,
	}})
	if err != nil {
		fmt.Println(err)
		return
	}
	source, err := funn.GetPackageSource("TcpFilter_Wifi")
	if err != nil {
		fmt.Println(err)
		return
	}
	source.Monitor(funnel.NewBaseMonitor(func(p gopacket.Packet) funnel.MonitorSign {
		ipLayer := p.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return funnel.CONTINUE
		}
		ip, _ := ipLayer.(*layers.IPv4)
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return funnel.CONTINUE
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 {
			fmt.Println("--------------------------------------")
			if bytes.Contains(tcp.Payload, []byte("DNSLOG")) {
				return funnel.TERMINATE
			}
			fmt.Println(string(tcp.Payload))
			fmt.Println(ip.SrcIP, ip.DstIP)
			fmt.Println(tcp.SrcPort, tcp.DstPort)
		}
		return funnel.CONTINUE
	}))

	funn.Wait()
}
