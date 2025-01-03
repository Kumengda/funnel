package funnel

import (
	"errors"
	"github.com/google/gopacket/pcap"
)

func checkDeviceName(des []HandleDes) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return errors.New("error finding devices:" + err.Error())
	}
	for _, hd := range des {
		flag := false
		for _, de := range devices {
			if de.Name == hd.DeviceName {
				flag = true
				break
			}
		}
		if !flag {
			return errors.New("error finding device name: " + hd.DeviceName)
		}
	}
	return nil
}
func stringInSlice(target string, slice []string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}
