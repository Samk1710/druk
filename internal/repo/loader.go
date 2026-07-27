package repo

import (
	"fmt"
	"strings"
)

// Load determines if target is local or remote, clones if remote, and returns the path to scan.
// It also returns a cleanup function to remove the temporary directory if one was created.
func Load(target string) (string, func(), error) {
	if target == "" || target == "." {
		return ".", func() {}, nil
	}

	isRemote := strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "github.com/")

	if isRemote {
		return "", nil, fmt.Errorf("remote repositories are not supported yet, please provide a local path")
	}

	return target, func() {}, nil
}
