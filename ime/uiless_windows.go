package ime

import (
	"github.com/hq0101/rdp-go/rail"
	"unsafe"
)

var iidThreadMgrEx = rail.GUID{Data1: 0x3e90ade3, Data2: 0x7594, Data3: 0x4cb0, Data4: [8]byte{0xbb, 0x58, 0x69, 0x62, 0x8f, 0x5f, 0x45, 0x8c}}

func (a *WindowsAdapter) activateThread(uiOnly bool) error {
	if !uiOnly {
		if hr := comCall(a.manager, 3, uintptr(unsafe.Pointer(&a.clientID))); hr != 0 {
			return hresult("ITfThreadMgr.Activate", hr)
		}
		a.active = true
		return nil
	}
	ex, err := queryCOM(a.manager, &iidThreadMgrEx)
	if err != nil {
		return err
	}
	defer comCall(ex, 2)
	if hr := comCall(ex, 14, uintptr(unsafe.Pointer(&a.clientID)), 4); hr != 0 {
		return hresult("ITfThreadMgrEx.ActivateEx", hr)
	}
	a.active = true // Cleanup must balance even if verification below fails.
	var flags uint32
	if hr := comCall(ex, 15, uintptr(unsafe.Pointer(&flags))); hr != 0 {
		return hresult("ITfThreadMgrEx.GetActiveFlags", hr)
	}
	if flags&4 == 0 {
		return rail.ErrUnsupported
	}
	return nil
}
