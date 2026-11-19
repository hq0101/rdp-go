package rdpdr

import "encoding/binary"

// Smartcard wire values from MS-RDPESC/MS-RDPEFS. The library frames device
// control IRPs only; per-IOCTL call/return structures (MS-RPCE NDR) and any
// reader or winscard semantics belong to the application backend. No local
// reader, service or winscard.dll is opened.
const (
	deviceTypeSmartcard uint32 = 0x20 // RDPDR_DTYP_SMARTCARD (MS-RDPEFS 2.2.1.3)

	// SCARD_IOCTL codes (MS-RDPESC 3.1.4). Only IRP_MJ_DEVICE_CONTROL requests
	// carry them; call/return layouts are the backend's responsibility.
	IOCTLEstablishContext       uint32 = 0x00090014
	IOCTLReleaseContext         uint32 = 0x00090018
	IOCTLIsValidContext         uint32 = 0x0009001c
	IOCTLListReaderGroupsA      uint32 = 0x00090020
	IOCTLListReaderGroupsW      uint32 = 0x00090024
	IOCTLListReadersA           uint32 = 0x00090028
	IOCTLListReadersW           uint32 = 0x0009002c
	IOCTLIntroduceReaderGroupA  uint32 = 0x00090050
	IOCTLIntroduceReaderGroupW  uint32 = 0x00090054
	IOCTLForgetReaderGroupA     uint32 = 0x00090058
	IOCTLForgetReaderGroupW     uint32 = 0x0009005c
	IOCTLIntroduceReaderA       uint32 = 0x00090060
	IOCTLIntroduceReaderW       uint32 = 0x00090064
	IOCTLForgetReaderA          uint32 = 0x00090068
	IOCTLForgetReaderW          uint32 = 0x0009006c
	IOCTLAddReaderToGroupA      uint32 = 0x00090070
	IOCTLAddReaderToGroupW      uint32 = 0x00090074
	IOCTLRemoveReaderFromGroupA uint32 = 0x00090078
	IOCTLRemoveReaderFromGroupW uint32 = 0x0009007c
	IOCTLLocateCardsA           uint32 = 0x00090098
	IOCTLLocateCardsW           uint32 = 0x0009009c
	IOCTLGetStatusChangeA       uint32 = 0x000900a0
	IOCTLGetStatusChangeW       uint32 = 0x000900a4
	IOCTLCancel                 uint32 = 0x000900a8
	IOCTLConnectA               uint32 = 0x000900ac
	IOCTLConnectW               uint32 = 0x000900b0
	IOCTLReconnect              uint32 = 0x000900b4
	IOCTLDisconnect             uint32 = 0x000900b8
	IOCTLBeginTransaction       uint32 = 0x000900bc
	IOCTLEndTransaction         uint32 = 0x000900c0
	IOCTLState                  uint32 = 0x000900c4
	IOCTLStatusA                uint32 = 0x000900c8
	IOCTLStatusW                uint32 = 0x000900cc
	IOCTLTransmit               uint32 = 0x000900d0
	IOCTLControl                uint32 = 0x000900d4
	IOCTLGetAttrib              uint32 = 0x000900d8
	IOCTLSetAttrib              uint32 = 0x000900dc
	// IOCTLAccessStartedEvent's call is a 4-byte Unused buffer that MUST be
	// ignored on receipt (MS-RDPESC 2.2.2.30); its return is a Long_Return.
	IOCTLAccessStartedEvent uint32 = 0x000900e0
	// SCARD_IOCTL_RELEASETARTEDEVENT [sic] is not used: no call or return
	// structure exists (MS-RDPESC 3.1.4.57).
	IOCTLReleaseStartedEvent uint32 = 0x000900e4
	IOCTLLocateCardsByATRA   uint32 = 0x000900e8
	IOCTLLocateCardsByATRW   uint32 = 0x000900ec
	IOCTLReadCacheA          uint32 = 0x000900f0
	IOCTLReadCacheW          uint32 = 0x000900f4
	IOCTLWriteCacheA         uint32 = 0x000900f8
	IOCTLWriteCacheW         uint32 = 0x000900fc
	IOCTLGetTransmitCount    uint32 = 0x00090100
	IOCTLGetReaderIcon       uint32 = 0x00090104
	IOCTLGetDeviceTypeId     uint32 = 0x00090108
)

// smartcardDosName is fixed by MS-RDPEFS 2.2.1.3: smartcard devices MUST use
// PreferredDosName "SCARD" and DeviceDataLength 0. Because the DOS name cannot
// vary, at most one smartcard device can be announced without colliding.
const smartcardDosName = "SCARD"

func validateSmartcards(ids []uint32) error {
	if len(ids) > MaxDevices {
		return ErrLimit
	}
	if len(ids) > 1 {
		return ErrDevice
	}
	return nil
}

// EncodeSmartcardAnnouncements encodes smartcard devices inside a Client
// Device List Announce: DeviceType 0x20, fixed "SCARD" DOS name, no device
// data. It accesses no local reader or service.
func EncodeSmartcardAnnouncements(ids []uint32) ([]byte, error) {
	if err := validateSmartcards(ids); err != nil {
		return nil, err
	}
	b := []byte{0x72, 0x44, 0x41, 0x44}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(ids)))
	for _, id := range ids {
		b = binary.LittleEndian.AppendUint32(b, deviceTypeSmartcard)
		b = binary.LittleEndian.AppendUint32(b, id)
		var name [8]byte
		copy(name[:], smartcardDosName)
		b = append(b, name[:]...)
		b = binary.LittleEndian.AppendUint32(b, 0)
	}
	return b, nil
}

// Smartcard control IRPs reuse the drive slice's ControlRequest framing
// (DR_CONTROL_REQ, MS-RDPEFS 2.2.1.4.5): OutputLength is the server-allocated
// response budget, Code the IoControlCode, Input the opaque per-IOCTL call
// body; the 20-byte Padding is ignored. Unknown codes are preserved:
// MS-RDPESC 3.1.4 requires invalid packets to be dropped without a reply,
// which the backend decides during dispatch.

// controlResponsePayload builds the DR_CONTROL_RSP parameters (MS-RDPEFS
// 2.2.1.5.5). Unlike generic file control replies, MS-RDPESC 3.1.4 allows
// output only with STATUS_SUCCESS: any other status MUST carry a zero
// OutputBufferLength and empty OutputBuffer. On success the output must fit
// the request's OutputLength.
func controlResponsePayload(q ControlRequest, status uint32, output []byte) ([]byte, error) {
	if status == StatusPending {
		return nil, ErrProtocol
	}
	if status != StatusSuccess {
		if len(output) != 0 {
			return nil, ErrProtocol
		}
		return make([]byte, 4), nil
	}
	if uint64(len(output)) > uint64(q.OutputLength) {
		return nil, ErrProtocol
	}
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(output)))
	return append(b, output...), nil
}
