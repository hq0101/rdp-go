package rdpgfx

import (
	"encoding/binary"
	"fmt"
)

// Profile selects implemented graphics capabilities. Configure it before
// the graphics channel opens and retain it until that channel closes.
type Profile uint8

const (
	// ProfileThinClient uses RemoteFX in place of Progressive, with a 16 MB cache.
	ProfileThinClient Profile = iota
	// ProfileProgressive offers Progressive with the SMALL_CACHE flag (16 MB).
	ProfileProgressive
	// ProfileAVC420 offers Version 8.1 AVC420/Progressive with a 16 MB cache,
	// plus Version 8 Progressive as fallback. It does not offer AVC444.
	ProfileAVC420
	// ProfileAVC444 offers Version 10.7 through 10.0 AVC444/444v2 and scaled
	// output where supported, with AVC420/Progressive fallback and a 16 MB cache.
	ProfileAVC444
)

func (p Profile) String() string {
	switch p {
	case ProfileThinClient:
		return "thin"
	case ProfileProgressive:
		return "progressive"
	case ProfileAVC420:
		return "avc420"
	case ProfileAVC444:
		return "avc444"
	default:
		return "unknown"
	}
}

func ParseProfile(value string) (Profile, error) {
	switch value {
	case "thin":
		return ProfileThinClient, nil
	case "progressive":
		return ProfileProgressive, nil
	case "avc420":
		return ProfileAVC420, nil
	case "avc444":
		return ProfileAVC444, nil
	default:
		return 0, fmt.Errorf("rdpgfx: profile must be thin, progressive, avc420 or avc444")
	}
}

func (p Profile) flags() (uint32, error) {
	switch p {
	case ProfileThinClient:
		return ThinClient, nil
	case ProfileProgressive:
		return SmallCache, nil
	case ProfileAVC420:
		return SmallCache | AVC420Enabled, nil
	case ProfileAVC444:
		return SmallCache | AVCThinClient, nil
	default:
		return 0, ErrUnsupported
	}
}

func (p Profile) capabilities() ([]Capability, error) {
	flags, err := p.flags()
	if err != nil {
		return nil, err
	}
	if p == ProfileAVC420 {
		return []Capability{{Version: Version81, Data: binary.LittleEndian.AppendUint32(nil, flags)},
			{Version: Version8, Data: binary.LittleEndian.AppendUint32(nil, SmallCache)}}, nil
	}
	if p == ProfileAVC444 {
		// Version 10.3 mandates 16 MB without a SMALL_CACHE flag. Version 10.1
		// has only reserved data and cannot request our bounded cache profile.
		var caps []Capability
		for _, v := range []uint32{Version107, Version106, Version105, Version104, Version103, Version102, Version10, Version81, Version8} {
			f := uint32(SmallCache)
			switch v {
			case Version107, Version106, Version105, Version104:
				f |= AVCThinClient
			case Version103:
				f = AVCThinClient
			case Version81:
				f |= AVC420Enabled
			}
			caps = append(caps, Capability{Version: v, Data: binary.LittleEndian.AppendUint32(nil, f)})
		}
		return caps, nil
	}
	return []Capability{{Version: Version8, Data: binary.LittleEndian.AppendUint32(nil, flags)}}, nil
}

func avcAllowed(version, flags uint32, codec uint16) bool {
	if version == Version81 {
		return codec == CodecAVC420 && flags&AVC420Enabled != 0
	}
	if flags&AVCDisabled != 0 {
		return false
	}
	switch version {
	case Version10:
		return codec == CodecAVC420 || codec == CodecAVC444
	case Version102, Version103, Version104, Version105, Version106, Version107:
		return codec == CodecAVC420 || codec == CodecAVC444 || codec == CodecAVC444V2
	}
	return false
}

func scaledOutputAllowed(version, flags uint32) bool {
	return version == Version105 || version == Version106 || version == Version107 && flags&ScaledMapDisable == 0
}

func (p Profile) accepts(c Capability) bool {
	caps, err := p.capabilities()
	if err != nil || len(c.Data) != 4 {
		return false
	}
	for _, offered := range caps {
		if c.Version != offered.Version {
			continue
		}
		want, got := binary.LittleEndian.Uint32(offered.Data), binary.LittleEndian.Uint32(c.Data)
		// The server confirms the effective flags, not necessarily a byte-for-byte
		// echo. Accept disabling AVC/scaling and clearing the AVC preference, but
		// retain our cache bound and codec profile. Subsequent PDUs are gated by
		// these confirmed flags (MS-RDPEGFX 1.7 and 3.3.5.19).
		var mutable uint32
		switch c.Version {
		case Version81:
			mutable = want & AVC420Enabled // may clear, never enable unoffered AVC
		case Version10, Version102:
			mutable = AVCDisabled
		case Version103, Version104, Version105, Version106, Version107:
			mutable = AVCDisabled | (want & AVCThinClient)
			if got&(AVCDisabled|AVCThinClient) == AVCDisabled|AVCThinClient {
				return false // mutually exclusive by section 2.2.3.6
			}
			if c.Version == Version107 {
				mutable |= ScaledMapDisable
			}
		}
		return got&^mutable == want&^mutable
	}
	return false
}
