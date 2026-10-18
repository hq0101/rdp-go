package rdpdr

import (
	"strings"
	"unicode/utf8"
)

// directoryPath translates RDPEFS separators, but never cleans an unsafe path
// into a different authorized one. Confinement is enforced again by os.Root.
func directoryPath(wire string) (string, error) {
	if !utf8.ValidString(wire) || len(wire) > MaxFilePathUnits*3 {
		return "", ErrProtocol
	}
	if wire == "" || wire == `\` {
		return ".", nil
	}
	if strings.HasPrefix(wire, `\`) {
		wire = wire[1:]
	}
	parts := strings.Split(wire, `\`)
	if len(parts) > 128 {
		return "", ErrLimit
	}
	total := 0
	for _, part := range parts {
		if !directoryComponent(part) {
			return "", ErrProtocol
		}
		for _, r := range part {
			total++
			if r > 0xffff {
				total++
			}
		}
	}
	if total+len(parts)-1 > MaxFilePathUnits {
		return "", ErrLimit
	}
	return strings.Join(parts, "/"), nil
}

func directoryComponent(name string) bool {
	if name == "" || name == "." || name == ".." || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") || !utf8.ValidString(name) {
		return false
	}
	units := 0
	for _, r := range name {
		if r < 32 || r == 127 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return false
		}
		units++
		if r > 0xffff {
			units++
		}
		if units > 255 {
			return false
		}
	}
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		tail := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
		if len([]rune(tail)) == 1 && strings.ContainsAny(tail, "123456789¹²³") {
			return false
		}
	}
	return true
}

// Directory selectors name a child of the already-open directory. Only the
// wildcard component is interpreted; it can never cause an additional open.
func directoryPattern(parent, wire string) (string, error) {
	if !utf8.ValidString(wire) || len(wire) > MaxFilePathUnits*3 {
		return "", ErrProtocol
	}
	if i := strings.LastIndex(wire, `\`); i >= 0 {
		prefix := wire[:i]
		p, err := directoryPath(prefix)
		if err != nil || p != parent {
			return "", ErrProtocol
		}
		wire = wire[i+1:]
	}
	if wire == "" {
		wire = "*"
	}
	units := 0
	for _, r := range wire {
		if r < 32 || r == 127 || strings.ContainsRune(`:/\|`, r) {
			return "", ErrProtocol
		}
		units++
		if r > 0xffff {
			units++
		}
		if units > 255 {
			return "", ErrLimit
		}
	}
	return wire, nil
}

// Windows selectors include DOS_STAR '<', DOS_QM '>' and DOS_DOT '"'. This
// bounded dynamic program avoids exponential wildcard backtracking.
func directoryMatch(pattern, name string) bool {
	if pattern == "*.*" {
		pattern = "*"
	}
	p, n := []rune(strings.ToUpper(pattern)), []rune(strings.ToUpper(name))
	lastDot := -1
	for i, r := range n {
		if r == '.' {
			lastDot = i
		}
	}
	next := make([]bool, len(n)+1)
	next[len(n)] = true
	for i := len(p) - 1; i >= 0; i-- {
		row := make([]bool, len(n)+1)
		for j := len(n); j >= 0; j-- {
			switch p[i] {
			case '*':
				row[j] = next[j] || j < len(n) && row[j+1]
			case '<':
				row[j] = next[j] || j < len(n) && j != lastDot && row[j+1]
			case '>':
				if j == len(n) || n[j] == '.' {
					row[j] = next[j]
				} else {
					row[j] = next[j+1]
				}
			case '"':
				row[j] = j == len(n) && next[j] || j < len(n) && n[j] == '.' && next[j+1]
			case '?':
				row[j] = j < len(n) && next[j+1]
			default:
				row[j] = j < len(n) && p[i] == n[j] && next[j+1]
			}
		}
		next = row
	}
	return next[0]
}
