//go:build linux && amd64

package passbolt

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -lpassbolt_ffi -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
import "C"
