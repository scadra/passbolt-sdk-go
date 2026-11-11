//go:build darwin && arm64

package passbolt

// #cgo LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -lpassbolt_ffi -framework Security -framework CoreFoundation -liconv -lSystem -lc -lm
import "C"
