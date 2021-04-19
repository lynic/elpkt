package elpkt

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

func IsIPv4Layer(data []byte) bool {
	if len(data) < HeaderIPv4Length {
		return false
	}
	if data[0]>>4 == 0x4 && int(binary.BigEndian.Uint16(data[2:4])) == len(data) && IPv4NextLayer(data) != LayerTypePayload {
		return true
	}
	return false
}

func IPv4NextLayer(data []byte) string {
	switch data[9] {
	// case layers.IPProtocolICMPv4:
	case 1:
		return LayerTypeICMPv4
	// case layers.IPProtocolTCP:
	case 6:
		return LayerTypeTCP
	// case layers.IPProtocolUDP:
	case 17:
		return LayerTypeUDP
	}
	return LayerTypePayload
}

func IsIPv6Layer(data []byte) bool {
	if len(data) < HeaderIPv6Length {
		return false
	}
	if data[0]>>4 == 0x6 && int(binary.BigEndian.Uint16(data[4:6])) == len(data)-40 && IPv6NextLayer(data) != LayerTypePayload {
		return true
	}
	return false
}

func IPv6NextLayer(data []byte) string {
	switch data[6] {
	// case layers.IPProtocolICMPv6:
	case 58:
		return LayerTypeICMPv6
	// case layers.IPProtocolTCP:
	case 6:
		return LayerTypeTCP
	// case layers.IPProtocolUDP:
	case 17:
		return LayerTypeUDP
	}
	return LayerTypePayload
}

func IPv6HeaderToBytes(ipv6 *layers.IPv6) []byte {
	// pLen := len(ipv6.Payload)
	bytes := make([]byte, 40)

	bytes[0] = (ipv6.Version << 4) | (ipv6.TrafficClass >> 4)
	bytes[1] = (ipv6.TrafficClass << 4) | uint8(ipv6.FlowLabel>>16)
	binary.BigEndian.PutUint16(bytes[2:], uint16(ipv6.FlowLabel))
	// ipv6.Length = uint16(pLen)
	binary.BigEndian.PutUint16(bytes[4:], ipv6.Length)
	bytes[6] = byte(ipv6.NextHeader)
	bytes[7] = byte(ipv6.HopLimit)
	// if err := ipv6.AddressTo16(); err != nil {
	// 	return nil
	// }
	copy(bytes[8:], ipv6.SrcIP)
	copy(bytes[24:], ipv6.DstIP)
	return bytes
}

func IPv4HeaderToBytes(ip *layers.IPv4) []byte {
	bytes := make([]byte, 20)
	ip.IHL = 5
	bytes[0] = (ip.Version << 4) | ip.IHL
	bytes[1] = ip.TOS
	binary.BigEndian.PutUint16(bytes[2:], ip.Length)
	binary.BigEndian.PutUint16(bytes[4:], ip.Id)
	var ff uint16
	ff |= uint16(ip.Flags) << 13
	ff |= ip.FragOffset
	binary.BigEndian.PutUint16(bytes[6:], ff)
	bytes[8] = ip.TTL
	bytes[9] = byte(ip.Protocol)

	copy(bytes[12:16], ip.SrcIP)
	copy(bytes[16:20], ip.DstIP)
	ip.Checksum = IPChecksum(bytes)
	binary.BigEndian.PutUint16(bytes[10:], ip.Checksum)
	return bytes
}
