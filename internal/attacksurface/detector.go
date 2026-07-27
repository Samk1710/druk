package attacksurface

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samk/druk/internal/model"
)

var (
	pyRouteRegex = regexp.MustCompile(`@(?:app|router|\w+)\.(?:route|get|post|put|delete|patch)\(`)
	pyDjangoRegex = regexp.MustCompile(`path\(|re_path\(`)
	goRouteRegex = regexp.MustCompile(`(?:http\.Handle|http\.HandleFunc|\w+\.(?:GET|POST|PUT|DELETE|PATCH))\(`)
	jsRouteRegex = regexp.MustCompile(`(?:app|router)\.(?:get|post|put|delete|patch|all)\(`)
)

func Detect(targetPath string) (model.AttackSurface, error) {
	var surface model.AttackSurface

	err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" && ext != ".py" && ext != ".js" && ext != ".ts" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 1
		for scanner.Scan() {
			line := scanner.Text()
			
			var fw string
			switch ext {
			case ".py":
				if pyRouteRegex.MatchString(line) {
					fw = "FastAPI/Flask"
				} else if strings.HasSuffix(path, "urls.py") && pyDjangoRegex.MatchString(line) {
					fw = "Django"
				}
			case ".go":
				if goRouteRegex.MatchString(line) {
					fw = "Go HTTP Router"
				}
			case ".js", ".ts":
				if jsRouteRegex.MatchString(line) {
					fw = "Express/Node Router"
				}
			}

			if fw != "" {
				relPath, _ := filepath.Rel(targetPath, path)
				surface.Entrypoints = append(surface.Entrypoints, model.Entrypoint{
					Path:      relPath,
					Line:      lineNum,
					Framework: fw,
				})
			}
			lineNum++
		}
		return nil
	})

	if err != nil {
		return surface, err
	}
	return surface, nil
}
