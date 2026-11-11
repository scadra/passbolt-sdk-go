//go:build darwin && amd64

package passbolt

// #cgo LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -lpassbolt_ffi -framework Security -framework CoreFoundation -liconv -lSystem -lc -lm
import "C"
