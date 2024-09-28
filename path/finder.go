package path

type Finder interface {
	Find(string, []string) bool
}

type DefaultFinder struct{}

func (d *DefaultFinder) Find(target string, paths []string) bool {
	for _, pattern := range paths {
		if isMatch(target, pattern) {
			return true
		}
	}
	return false
}

func isMatch(t, p string) bool {
	n := len(t)
	m := len(p)
	i, j := 0, 0
	startIndex := -1
	match := 0

	for i < n {
		if j < m && (p[j] == '?' || p[j] == t[i]) {
			i++
			j++
		} else if j < m && p[j] == '*' {
			startIndex = j
			match = i
			j++
		} else if startIndex != -1 {
			j = startIndex + 1
			match++
			i = match
		} else {
			return false
		}
	}

	for j < m && p[j] == '*' {
		j++
	}

	return j == m
}
