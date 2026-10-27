//go:build linux && arm64

package passbolt_ffi

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -lpassbolt_ffi -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
import "C"
