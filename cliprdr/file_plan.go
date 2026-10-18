package cliprdr

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxFileTreeDepth = 32
const MaxFileTreeEntries = 8192

var (
	ErrFilePath        = errors.New("cliprdr: unsafe or unsupported file path")
	ErrFileCollision   = errors.New("cliprdr: conflicting file or directory names")
	ErrFileSizeUnknown = errors.New("cliprdr: query all file sizes before planning")
	ErrFileIncomplete  = errors.New("cliprdr: file batch is incomplete")
)

// FilePlanOptions imposes explicit content quotas. Zero permits only empty
// files/directories. All regular files must have a known size before planning.
type FilePlanOptions struct {
	MaxFileSize, MaxTotalSize uint64
}

type FilePlanEntry struct {
	// Index is the original descriptor index, or -1 for an implicit parent.
	Index     int
	Path      string // slash-separated, relative; never a local filesystem path
	Directory bool
	Size      uint64
}

// FilePlan is an immutable snapshot; Client.PlanFiles also binds its connection.
// Entries returns a copy.
// Planning does not read files, create directories, or change the clipboard.
type FilePlan struct {
	set     FileSet
	entries []FilePlanEntry
	byIndex map[uint32]int
	total   uint64
}

func (p *FilePlan) Entries() []FilePlanEntry { return append([]FilePlanEntry(nil), p.entries...) }
func (p *FilePlan) TotalSize() uint64        { return p.total }

// PlanFiles validates a complete remote group without changing its indices.
// For unknown sizes, issue RequestFileSize and consume its result first, then
// retry planning. Directories are never requested as file contents.
// Names preserve Unicode but are checked using Windows portable naming rules.
// Case-fold aliases are rejected; Unicode normalization and filesystem-specific
// aliases (e.g. 8.3) are NOT resolved. No automatic rename or overwrite occurs.
func (c *Client) PlanFiles(set FileSet, options FilePlanOptions) (*FilePlan, error) {
	s, err := c.remoteFileSet(set)
	if err != nil {
		return nil, err
	}
	return planFiles(set, s.files, options)
}

// PlanFileOffer validates explicitly selected local descriptors before any I/O
// or publication. The result is not bound to a remote group and cannot authorize
// downloads. This applies the same portable tree and quota rules as PlanFiles.
func PlanFileOffer(files []FileDescriptor, options FilePlanOptions) (*FilePlan, error) {
	if len(files) == 0 {
		return nil, ErrFile
	}
	return planFiles(FileSet{}, files, options)
}

func planFiles(set FileSet, files []FileDescriptor, options FilePlanOptions) (*FilePlan, error) {
	if len(files) > MaxFiles || options.MaxFileSize > math.MaxInt64 || options.MaxTotalSize > math.MaxInt64 {
		return nil, ErrFileLimit
	}
	p := &FilePlan{set: set, byIndex: make(map[uint32]int)}
	names := make(map[string]int)
	for index, file := range files {
		parts, err := filePathParts(file.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", err, file.Name)
		}
		if !file.IsDirectory() {
			if file.Flags&FileSizeValid == 0 {
				return nil, ErrFileSizeUnknown
			}
			if file.Size > options.MaxFileSize || file.Size > options.MaxTotalSize-p.total {
				return nil, ErrFileLimit
			}
			p.total += file.Size
		}
		for depth := range parts {
			path := strings.Join(parts[:depth+1], "/")
			key := foldFilePath(path)
			last := depth == len(parts)-1
			directory := !last || file.IsDirectory()
			if old, ok := names[key]; ok {
				e := &p.entries[old]
				if e.Path != path || !e.Directory || !directory || (last && e.Index >= 0) {
					return nil, fmt.Errorf("%w: %q", ErrFileCollision, path)
				}
				if last {
					e.Index = index
					p.byIndex[uint32(index)] = old
				}
				continue
			}
			if len(p.entries) >= MaxFileTreeEntries {
				return nil, ErrFileLimit
			}
			e := FilePlanEntry{Index: -1, Path: path, Directory: directory}
			if last {
				e.Index = index
				if !directory {
					e.Size = file.Size
				}
				p.byIndex[uint32(index)] = len(p.entries)
			}
			names[key] = len(p.entries)
			p.entries = append(p.entries, e)
		}
	}
	return p, nil
}

func filePathParts(name string) ([]string, error) {
	if name == "" || !utf8.ValidString(name) || len(name) > 4*259 || len(utf16.Encode([]rune(name))) > 259 {
		return nil, ErrFilePath
	}
	parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
	if len(parts) > MaxFileTreeDepth {
		return nil, ErrFileLimit
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return nil, ErrFilePath
		}
		for _, r := range part {
			if unicode.IsControl(r) || strings.ContainsRune(`<>:"|?*`, r) {
				return nil, ErrFilePath
			}
		}
		base, _, _ := strings.Cut(part, ".")
		base = strings.ToUpper(strings.TrimRight(base, " "))
		switch base {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
			return nil, ErrFilePath
		}
		if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
			suffix := base[3:]
			if utf8.RuneCountInString(suffix) == 1 && strings.ContainsAny(suffix, "123456789¹²³") {
				return nil, ErrFilePath
			}
		}
	}
	return parts, nil
}

func foldFilePath(s string) string {
	return strings.Map(func(r rune) rune {
		minRune := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minRune {
				minRune = next
			}
		}
		return minRune
	}, s)
}
