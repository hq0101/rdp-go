package rdpdr

import (
	"io/fs"
	"syscall"
	"time"
)

func directorySupportedTimes() uint32 { return directoryTimeAccess | directoryTimeWrite }

func directoryBasicInfo(info fs.FileInfo) BasicInformation {
	b := directoryFallbackBasic(info)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		b.LastAccessTime = directoryTime(time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)))
		b.LastWriteTime = directoryTime(time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)))
		b.ChangeTime = directoryTime(time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)))
	}
	// Stat_t has no birth time on Linux; zero means unavailable, not mtime.
	return b
}
