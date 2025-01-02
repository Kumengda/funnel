package main

import (
	"fmt"
	"github.com/Kumengda/funnel/funnel"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	funn := funnel.NewFunnel()
	err := funn.SetHandles([]funnel.HandleDes{{
		Name:       "wifi",
		Bpfilter:   "tcp",
		DeviceName: "en0",
		Promisc:    true,
		Timeout:    pcap.BlockForever,
	}})
	if err != nil {
		fmt.Println(err)
		return
	}
	source, err := funn.GetPackageSource("wifi")
	if err != nil {
		fmt.Println(err)
		return
	}
	for packet := range source.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 {
			fmt.Println("--------------------------------------")
			fmt.Println(string(tcp.Payload))
			fmt.Println(ip.SrcIP, ip.DstIP)
			fmt.Println(tcp.SrcPort, tcp.DstPort)
		}
	}
}
