package main

import (
	"fmt"
	"os"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/tasks/release"
)

func main() {
	Makefile(
		// npm-based build/test/lint wrappers
		Task{
			Name:        "bootstrap",
			Description: "install npm dependencies",
			Run:         func() { Run("npm ci") },
		},
		Task{
			Name:        "build",
			Description: "build the action distributable (dist/index.js)",
			Run:         func() { Run("npm run build") },
		},
		Task{
			Name:        "static-analysis",
			Description: "run lint and format check",
			Run: func() {
				Run("npm run lint")
				Run("npx prettier --check *.js tests/*.js")
			},
		},
		Task{
			Name:        "unit",
			Description: "run unit tests",
			Run:         func() { Run("npm test") },
		},

		// repins GrypeVersion.js to the latest published grype release and
		// rebuilds dist/. Intended to be run by a maintainer (or from a fork)
		// who can then commit the diff and open a PR by hand. Requires `gh`
		// to be authenticated (gh auth login).
		Task{
			Name:        "update-grype-release",
			Description: "bump GrypeVersion.js to the latest grype release and rebuild dist/",
			Run: func() {
				version := strings.TrimSpace(Run(`gh release view --json name -q '.name' -R anchore/grype`))
				if version == "" {
					panic("could not determine latest grype release")
				}
				content := fmt.Sprintf("export const GRYPE_VERSION = %q;\n", version)
				if err := os.WriteFile("GrypeVersion.js", []byte(content), 0o644); err != nil {
					panic(err)
				}
				fmt.Printf("pinned grype to %s; rebuilding dist/...\n", version)
				Run("npm ci")
				Run("npm run build")
				fmt.Printf("done. Review with `git diff GrypeVersion.js dist/` and commit.\n")
			},
		},

		// chronicle-based changelog, gh-cli triggered release.yaml dispatch,
		// and ci-release tag+release task (run from inside release.yaml).
		release.Tasks(),
	)
}
