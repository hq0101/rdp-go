package nativeview

import (
	"errors"
	"image"
	"unsafe"

	"github.com/hq0101/rdp-go/graphics"
)

var (
	createBitmapDC = gdi32.NewProc("CreateCompatibleDC")
	createDIB      = gdi32.NewProc("CreateDIBSection")
	deleteBitmapDC = gdi32.NewProc("DeleteDC")
	stretchBitmap  = gdi32.NewProc("StretchBlt")
	flushBitmap    = gdi32.NewProc("GdiFlush")
	bitmapClipBox  = gdi32.NewProc("GetClipBox")
)

type dibStretch func(uintptr, image.Rectangle, *bitmapHeader, []byte) (int32, error)

func stretchPixels(dc uintptr, dst image.Rectangle, header *bitmapHeader, pixels []byte) (int32, error) {
	r, _, e := stretchDIBits.Call(dc, signed(int32(dst.Min.X)), signed(int32(dst.Min.Y)), uintptr(dst.Dx()), uintptr(dst.Dy()), 0, 0, uintptr(header.Width), uintptr(-header.Height), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(header)), 0, 0x00cc0020)
	return int32(r), e
}

// Paint is owned by the locked window thread. StretchDIBits returns zero for
// BOTH failure and an entirely clipped draw; LastError may still be zero.
// When visible pixels remain, recover once via a native DIB and StretchBlt.
// The fallback is also used for GDI_ERROR; neither path retries indefinitely.
func drawDesktopBitmap(dc uintptr, dst image.Rectangle, size image.Point, pixels []byte, direct dibStretch) error {
	if dc == 0 || direct == nil || dst.Empty() || dst.Min.X < -32768 || dst.Min.Y < -32768 || dst.Max.X > 32768 || dst.Max.Y > 32768 || size.X < 1 || size.Y < 1 || size.X > 8192 || size.Y > 8192 || int64(size.X)*int64(size.Y) > graphics.MaxPixels || int64(len(pixels)) != 4*int64(size.X)*int64(size.Y) {
		return ErrInvalid
	}
	header := bitmapHeader{Size: 40, Width: int32(size.X), Height: -int32(size.Y), Planes: 1, Bits: 32}
	result, original := direct(dc, dst, &header, pixels)
	if result > 0 {
		return nil
	}
	original = nativeError("StretchDIBits", original)
	if result == 0 {
		var clip winRect
		kind, _, e := bitmapClipBox.Call(dc, uintptr(unsafe.Pointer(&clip)))
		if kind == 0 {
			return errors.Join(original, nativeError("GetClipBox", e))
		}
		if kind == 1 || dst.Intersect(image.Rect(int(clip.Left), int(clip.Top), int(clip.Right), int(clip.Bottom))).Empty() {
			return nil
		}
	}
	if err := drawNativeBitmap(dc, dst, &header, pixels); err != nil {
		return errors.Join(original, err)
	}
	return nil
}

// Create a source compatible with this destination device. Copy the bounded
// BGRA bytes to its own native allocation; the destination's clip and stretch
// settings are preserved. No process/global drawing policy is changed.
func drawNativeBitmap(dc uintptr, dst image.Rectangle, header *bitmapHeader, pixels []byte) (err error) {
	mem, _, e := createBitmapDC.Call(dc)
	if mem == 0 {
		return nativeError("CreateCompatibleDC", e)
	}
	var bitmap, old uintptr
	submitted := false
	defer func() {
		// Finish any queued read of the source before releasing its storage.
		if submitted {
			if ok, _, e := flushBitmap.Call(); ok == 0 {
				err = errors.Join(err, nativeError("GdiFlush", e))
			}
		}
		if old != 0 {
			if restored, _, e := selectObject.Call(mem, old); restored == 0 || restored == ^uintptr(0) {
				err = errors.Join(err, nativeError("SelectObject restore bitmap", e))
			}
		}
		// Deleting the memory DC also deselects the bitmap if restoration failed.
		if ok, _, e := deleteBitmapDC.Call(mem); ok == 0 {
			err = errors.Join(err, nativeError("DeleteDC", e))
		}
		if bitmap != 0 {
			if ok, _, e := deleteObject.Call(bitmap); ok == 0 {
				err = errors.Join(err, nativeError("DeleteObject bitmap", e))
			}
		}
	}()
	var bits uintptr
	bitmap, _, e = createDIB.Call(mem, uintptr(unsafe.Pointer(header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bitmap == 0 || bits == 0 {
		return nativeError("CreateDIBSection", e)
	}
	old, _, e = selectObject.Call(mem, bitmap)
	if old == 0 || old == ^uintptr(0) {
		old = 0
		return nativeError("SelectObject bitmap", e)
	}
	copyNative.Call(bits, uintptr(unsafe.Pointer(&pixels[0])), uintptr(len(pixels)))
	submitted = true
	if ok, _, e := stretchBitmap.Call(dc, signed(int32(dst.Min.X)), signed(int32(dst.Min.Y)), uintptr(dst.Dx()), uintptr(dst.Dy()), mem, 0, 0, uintptr(header.Width), uintptr(-header.Height), 0x00cc0020); ok == 0 {
		return nativeError("StretchBlt", e)
	}
	return nil
}
