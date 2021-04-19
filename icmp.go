package elpkt

import (
	"encoding/binary"
)

func ICMPType(data []byte) uint8 {
	return uint8(data[0])
}

func ICMPCode(data []byte) uint8 {
	return uint8(data[1])
}

type ICMPLayer struct {
	Layer
}

func (l *ICMPLayer) GetType(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart+0])
}

func (l *ICMPLayer) GetCode(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart+1])
}

func (l *ICMPLayer) GetId(p *Packet) uint16 {
	return binary.BigEndian.Uint16(p.Data[l.DataStart+4 : l.DataStart+6])
}

func (l *ICMPLayer) GetMTU(p *Packet) uint16 {
	if l.Type == LayerTypeICMPv4 {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+7 : l.DataStart+9])
	}
	if l.Type == LayerTypeICMPv6 {
		mtu := binary.BigEndian.Uint32(p.Data[l.DataStart+4 : l.DataStart+9])
		return uint16(mtu)
	}
	return 0
}

func (l *ICMPLayer) SetMTU(p *Packet, mtu uint16) {
	if l.Type == LayerTypeICMPv4 {
		binary.BigEndian.PutUint16(p.Data[l.DataStart+7:], mtu)
	}
	if l.Type == LayerTypeICMPv6 {
		v := uint32(mtu)
		binary.BigEndian.PutUint32(p.Data[l.DataStart+4:], v)
	}
}

// func ICMPv6HeaderToBytes(i *layers.ICMPv6) []byte {
// 	bytes := make([]byte, 4)
// 	binary.BigEndian.PutUint16(bytes, uint16(i.TypeCode))
// 	// clear checksum
// 	bytes[2] = 0
// 	bytes[3] = 0
// 	return bytes
// }
