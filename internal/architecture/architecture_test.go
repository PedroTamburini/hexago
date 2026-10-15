// Package architecture holds structural tests that enforce the hexagonal
// dependency rule. They are intentionally kept out of the domain packages so
// they run as part of the normal `go test ./...` without being imported anywhere.
package architecture

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/PedroTamburini/hexago"

// packageInfo mirrors the subset of `go list -json` used by the checks below.
type packageInfo struct {
	ImportPath string
	Imports    []string
}

// forbiddenFrameworkPrefixes are third party packages the core must not depend
// on, because doing so would tie the domain to a delivery or persistence
// technology.
var forbiddenFrameworkPrefixes = []string{
	"github.com/gin-gonic/gin",
	"gorm.io/",
	"github.com/redis/go-redis/",
	"github.com/swaggo/",
}

func TestHexagonalDependencyDirection(t *testing.T) {
	packages := listPackages(t)

	if len(packages) == 0 {
		t.Fatal("go list returned no packages")
	}

	for _, pkg := range packages {
		rel := strings.TrimPrefix(pkg.ImportPath, modulePath+"/")
		if rel == pkg.ImportPath {
			// Not part of this module (e.g. standard library); skip.
			continue
		}

		for _, imported := range pkg.Imports {
			if !strings.HasPrefix(imported, modulePath+"/") {
				// External import: only the core layer is restricted.
				if isCore(rel) && hasAnyPrefix(imported, forbiddenFrameworkPrefixes) {
					t.Errorf("%s must not import framework %q", pkg.ImportPath, imported)
				}
				continue
			}

			importedRel := strings.TrimPrefix(imported, modulePath+"/")

			switch {
			case isCore(rel) && (isAdapter(importedRel) || isInfrastructure(importedRel)):
				t.Errorf("core package %s must not import %s", pkg.ImportPath, imported)
			case isAdapter(rel) && isInfrastructure(importedRel):
				t.Errorf("adapter package %s must not import infrastructure %s", pkg.ImportPath, imported)
			case isInfrastructure(rel) && isAdapter(importedRel):
				t.Errorf("infrastructure package %s must not import adapter %s", pkg.ImportPath, imported)
			}
		}
	}
}

func listPackages(t *testing.T) []packageInfo {
	t.Helper()

	cmd := exec.Command("go", "list", "-json", "./...")
	// Tests run with the working directory set to this package, so point go list
	// at the module root instead.
	cmd.Dir = filepath.Join("..", "..")

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}

	var packages []packageInfo

	decoder := json.NewDecoder(bytes.NewReader(output))
	for decoder.More() {
		var pkg packageInfo
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		packages = append(packages, pkg)
	}

	return packages
}

func isCore(rel string) bool {
	return strings.HasPrefix(rel, "internal/core/")
}

func isAdapter(rel string) bool {
	return strings.HasPrefix(rel, "internal/adapter/")
}

func isInfrastructure(rel string) bool {
	return strings.HasPrefix(rel, "internal/infrastructure/")
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	return false
}
