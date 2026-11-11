package passbolt

// #include <passbolt.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"runtime/cgo"
	"sync/atomic"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type goRustBuffer struct {
	inner C.RustBuffer
}

type rustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type externalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func rustBufferFromC(b C.RustBuffer) externalCRustBuffer {
	return goRustBuffer{
		inner: b,
	}
}

func cFromRustBuffer(b externalCRustBuffer) C.RustBuffer {
	return C.RustBuffer{
		capacity: C.uint64_t(b.Capacity()),
		len:      C.uint64_t(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func rustBufferFromExternal(b externalCRustBuffer) goRustBuffer {
	return goRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb goRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb goRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb goRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb goRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb goRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_passbolt_ffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb goRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_passbolt_ffi_rustbuffer_from_bytes(foreign, status)
	})
}

type bufLifter[GoType any] interface {
	Lift(value rustBufferI) GoType
}

type bufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type uniffiBufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type uniffiBufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func lowerIntoRustBuffer[GoType any](bufWriter uniffiBufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func liftFromRustBuffer[GoType any](bufReader uniffiBufReader[GoType], rbuf rustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter uniffiBufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter uniffiBufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return liftFromRustBuffer(converter, goRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", ffiConverterStringINSTANCE.Lift(goRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", ffiConverterStringINSTANCE.Lift(goRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type nativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 29
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_passbolt_ffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_decrypt_message()
		})
		if checksum != 43055 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_decrypt_message: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_default_password_policies()
		})
		if checksum != 23602 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_default_password_policies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_encrypt_message()
		})
		if checksum != 32734 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_encrypt_message: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_fetch_server_key()
		})
		if checksum != 43820 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_fetch_server_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_generate_passphrase()
		})
		if checksum != 13290 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_generate_passphrase: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_generate_password()
		})
		if checksum != 4206 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_generate_password: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_generate_pin_code()
		})
		if checksum != 47707 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_generate_pin_code: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_generate_secret()
		})
		if checksum != 40666 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_generate_secret: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_get_key_fingerprint()
		})
		if checksum != 20754 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_get_key_fingerprint: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_secret_entropy()
		})
		if checksum != 45641 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_secret_entropy: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_func_secret_strength()
		})
		if checksum != 52436 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_secret_strength: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_add_favorite()
		})
		if checksum != 18663 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_add_favorite: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_add_tag_to_resource()
		})
		if checksum != 19029 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_add_tag_to_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_base_url()
		})
		if checksum != 9342 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_base_url: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_check_auth()
		})
		if checksum != 32798 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_check_auth: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_check_password_pwned()
		})
		if checksum != 8996 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_check_password_pwned: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_comment()
		})
		if checksum != 33152 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_comment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_folder()
		})
		if checksum != 8701 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_group()
		})
		if checksum != 64914 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_resource()
		})
		if checksum != 43960 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_user()
		})
		if checksum != 40697 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_create_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_decrypt_resource_secret()
		})
		if checksum != 60138 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_decrypt_resource_secret: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_comment()
		})
		if checksum != 43322 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_comment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_folder()
		})
		if checksum != 59847 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_folder_with_content()
		})
		if checksum != 39210 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_folder_with_content: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group()
		})
		if checksum != 60464 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group_dry_run()
		})
		if checksum != 64259 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group_dry_run: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group_with_transfer()
		})
		if checksum != 56759 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_group_with_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_password_expiry_settings()
		})
		if checksum != 39700 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_resource()
		})
		if checksum != 61657 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_resources()
		})
		if checksum != 51176 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_resources: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_tag()
		})
		if checksum != 43240 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_tag: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user()
		})
		if checksum != 20454 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user_dry_run()
		})
		if checksum != 28228 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user_dry_run: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user_with_transfer()
		})
		if checksum != 7508 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_delete_user_with_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_comments()
		})
		if checksum != 31825 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_comments: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder()
		})
		if checksum != 5949 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder_permissions()
		})
		if checksum != 47086 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder_permissions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder_tree()
		})
		if checksum != 5436 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_folder_tree: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_group()
		})
		if checksum != 12339 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_me()
		})
		if checksum != 26717 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_me: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_metadata_keys_settings()
		})
		if checksum != 61321 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_metadata_keys_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_metadata_types_settings()
		})
		if checksum != 21286 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_metadata_types_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_password_expiry_settings()
		})
		if checksum != 62782 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_password_policies()
		})
		if checksum != 36525 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_password_policies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource()
		})
		if checksum != 38562 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource_permissions()
		})
		if checksum != 62528 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource_permissions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource_view()
		})
		if checksum != 36663 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resource_view: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resources_by_ids()
		})
		if checksum != 45371 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_resources_by_ids: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_tags()
		})
		if checksum != 16759 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_tags: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_user()
		})
		if checksum != 23707 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_get_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_group_delete_blockers()
		})
		if checksum != 24182 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_group_delete_blockers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_keep_alive()
		})
		if checksum != 5643 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_keep_alive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_folders()
		})
		if checksum != 62952 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_folders: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_groups()
		})
		if checksum != 14170 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_groups: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resource_types()
		})
		if checksum != 58890 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resource_types: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resource_views()
		})
		if checksum != 11201 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resource_views: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resources()
		})
		if checksum != 11019 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_resources: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_users()
		})
		if checksum != 21801 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_list_users: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_logout()
		})
		if checksum != 31138 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_logout: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_metadata_key_fingerprint()
		})
		if checksum != 47873 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_metadata_key_fingerprint: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_move_folder()
		})
		if checksum != 9526 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_move_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_move_resource()
		})
		if checksum != 19495 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_move_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_remove_favorite()
		})
		if checksum != 36149 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_remove_favorite: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_rename_folder()
		})
		if checksum != 30356 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_rename_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_rename_tag()
		})
		if checksum != 1252 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_rename_tag: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_metadata_keys_settings()
		})
		if checksum != 53283 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_metadata_keys_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_metadata_types_settings()
		})
		if checksum != 49801 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_metadata_types_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_password_expiry_settings()
		})
		if checksum != 41730 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_password_policies()
		})
		if checksum != 42377 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_save_password_policies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_search_aros()
		})
		if checksum != 2246 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_search_aros: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_set_resource_tags()
		})
		if checksum != 17775 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_set_resource_tags: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_share_folder()
		})
		if checksum != 15354 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_share_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_share_resource()
		})
		if checksum != 17791 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_share_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_group()
		})
		if checksum != 18275 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_resource()
		})
		if checksum != 58897 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_user()
		})
		if checksum != 11291 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_update_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_user_delete_blockers()
		})
		if checksum != 46932 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_user_delete_blockers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_user_id()
		})
		if checksum != 43817 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_asyncpassboltclient_user_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_add_favorite()
		})
		if checksum != 9884 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_add_favorite: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_add_tag_to_resource()
		})
		if checksum != 41512 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_add_tag_to_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_base_url()
		})
		if checksum != 36002 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_base_url: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_check_auth()
		})
		if checksum != 36888 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_check_auth: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_check_password_pwned()
		})
		if checksum != 22452 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_check_password_pwned: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_comment()
		})
		if checksum != 27711 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_comment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_folder()
		})
		if checksum != 7275 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_group()
		})
		if checksum != 52654 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_resource()
		})
		if checksum != 16509 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_user()
		})
		if checksum != 32219 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_decrypt_resource_secret()
		})
		if checksum != 7524 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_decrypt_resource_secret: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_comment()
		})
		if checksum != 2571 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_comment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder()
		})
		if checksum != 19135 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder_with_content()
		})
		if checksum != 22029 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder_with_content: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group()
		})
		if checksum != 47616 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_dry_run()
		})
		if checksum != 22289 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_dry_run: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_with_transfer()
		})
		if checksum != 35919 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_with_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_password_expiry_settings()
		})
		if checksum != 50429 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resource()
		})
		if checksum != 29643 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resources()
		})
		if checksum != 37147 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resources: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_tag()
		})
		if checksum != 10384 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_tag: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user()
		})
		if checksum != 4816 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_dry_run()
		})
		if checksum != 50056 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_dry_run: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_with_transfer()
		})
		if checksum != 26660 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_with_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_comments()
		})
		if checksum != 46526 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_comments: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder()
		})
		if checksum != 33723 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_permissions()
		})
		if checksum != 7501 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_permissions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_tree()
		})
		if checksum != 14196 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_tree: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_group()
		})
		if checksum != 41407 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_me()
		})
		if checksum != 45450 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_me: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_keys_settings()
		})
		if checksum != 6183 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_keys_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_types_settings()
		})
		if checksum != 15905 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_types_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_expiry_settings()
		})
		if checksum != 11190 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_policies()
		})
		if checksum != 53383 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_policies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource()
		})
		if checksum != 40288 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_permissions()
		})
		if checksum != 38750 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_permissions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_view()
		})
		if checksum != 43285 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_view: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resources_by_ids()
		})
		if checksum != 49165 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resources_by_ids: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_tags()
		})
		if checksum != 15194 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_tags: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_user()
		})
		if checksum != 35656 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_group_delete_blockers()
		})
		if checksum != 22301 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_group_delete_blockers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_keep_alive()
		})
		if checksum != 28453 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_keep_alive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_folders()
		})
		if checksum != 15967 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_folders: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_groups()
		})
		if checksum != 26466 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_groups: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_types()
		})
		if checksum != 9081 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_types: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_views()
		})
		if checksum != 47359 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_views: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resources()
		})
		if checksum != 32482 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resources: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_users()
		})
		if checksum != 46077 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_users: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_logout()
		})
		if checksum != 4001 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_logout: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_metadata_key_fingerprint()
		})
		if checksum != 61684 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_metadata_key_fingerprint: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_move_folder()
		})
		if checksum != 36224 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_move_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_move_resource()
		})
		if checksum != 59983 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_move_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_remove_favorite()
		})
		if checksum != 1199 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_remove_favorite: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_rename_folder()
		})
		if checksum != 36393 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_rename_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_rename_tag()
		})
		if checksum != 4571 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_rename_tag: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_keys_settings()
		})
		if checksum != 54164 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_keys_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_types_settings()
		})
		if checksum != 3587 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_types_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_expiry_settings()
		})
		if checksum != 11965 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_expiry_settings: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_policies()
		})
		if checksum != 13562 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_policies: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_search_aros()
		})
		if checksum != 20833 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_search_aros: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_set_resource_tags()
		})
		if checksum != 1861 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_set_resource_tags: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_share_folder()
		})
		if checksum != 5214 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_share_folder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_share_resource()
		})
		if checksum != 28674 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_share_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_group()
		})
		if checksum != 40055 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_group: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_resource()
		})
		if checksum != 57566 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_resource: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_user()
		})
		if checksum != 41303 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_user: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_user_delete_blockers()
		})
		if checksum != 63745 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_user_delete_blockers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_method_passboltclient_user_id()
		})
		if checksum != 15516 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_user_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_constructor_asyncpassboltclient_login()
		})
		if checksum != 14105 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_asyncpassboltclient_login: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_constructor_asyncpassboltclient_login_with_config()
		})
		if checksum != 25394 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_asyncpassboltclient_login_with_config: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_constructor_passboltclient_login()
		})
		if checksum != 42934 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_passboltclient_login: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_config()
		})
		if checksum != 36731 {
			// If this happens try cleaning and rebuilding your project
			panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_config: UniFFI API checksum mismatch")
		}
	}
}

type ffiConverterUint16 struct{}

var ffiConverterUint16INSTANCE = ffiConverterUint16{}

func (ffiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (ffiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (ffiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (ffiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type ffiDestroyerUint16 struct{}

func (ffiDestroyerUint16) Destroy(_ uint16) {}

type ffiConverterUint32 struct{}

var ffiConverterUint32INSTANCE = ffiConverterUint32{}

func (ffiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (ffiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (ffiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (ffiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type ffiDestroyerUint32 struct{}

func (ffiDestroyerUint32) Destroy(_ uint32) {}

type ffiConverterInt32 struct{}

var ffiConverterInt32INSTANCE = ffiConverterInt32{}

func (ffiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (ffiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (ffiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (ffiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type ffiDestroyerInt32 struct{}

func (ffiDestroyerInt32) Destroy(_ int32) {}

type ffiConverterUint64 struct{}

var ffiConverterUint64INSTANCE = ffiConverterUint64{}

func (ffiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (ffiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (ffiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (ffiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type ffiDestroyerUint64 struct{}

func (ffiDestroyerUint64) Destroy(_ uint64) {}

type ffiConverterFloat64 struct{}

var ffiConverterFloat64INSTANCE = ffiConverterFloat64{}

func (ffiConverterFloat64) Lower(value float64) C.double {
	return C.double(value)
}

func (ffiConverterFloat64) Write(writer io.Writer, value float64) {
	writeFloat64(writer, value)
}

func (ffiConverterFloat64) Lift(value C.double) float64 {
	return float64(value)
}

func (ffiConverterFloat64) Read(reader io.Reader) float64 {
	return readFloat64(reader)
}

type ffiDestroyerFloat64 struct{}

func (ffiDestroyerFloat64) Destroy(_ float64) {}

type ffiConverterBool struct{}

var ffiConverterBoolINSTANCE = ffiConverterBool{}

func (ffiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (ffiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (ffiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (ffiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type ffiDestroyerBool struct{}

func (ffiDestroyerBool) Destroy(_ bool) {}

type ffiConverterString struct{}

var ffiConverterStringINSTANCE = ffiConverterString{}

func (ffiConverterString) Lift(rb rustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (ffiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (ffiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c ffiConverterString) LowerExternal(value string) externalCRustBuffer {
	return rustBufferFromC(stringToRustBuffer(value))
}

func (ffiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type ffiDestroyerString struct{}

func (ffiDestroyerString) Destroy(_ string) {}

type ffiConverterBytes struct{}

var ffiConverterBytesINSTANCE = ffiConverterBytes{}

func (c ffiConverterBytes) Lower(value []byte) C.RustBuffer {
	return lowerIntoRustBuffer[[]byte](c, value)
}

func (c ffiConverterBytes) LowerExternal(value []byte) externalCRustBuffer {
	return rustBufferFromC(c.Lower(value))
}

func (c ffiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c ffiConverterBytes) Lift(rb rustBufferI) []byte {
	return liftFromRustBuffer[[]byte](c, rb)
}

func (c ffiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type ffiDestroyerBytes struct{}

func (ffiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type uniffiFfiObject struct {
	pointer       unsafe.Pointer
	callCounter   atomic.Int64
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer
	freeFunction  func(unsafe.Pointer, *C.RustCallStatus)
	destroyed     atomic.Bool
}

func newFfiObject(
	pointer unsafe.Pointer,
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer,
	freeFunction func(unsafe.Pointer, *C.RustCallStatus),
) uniffiFfiObject {
	return uniffiFfiObject{
		pointer:       pointer,
		cloneFunction: cloneFunction,
		freeFunction:  freeFunction,
	}
}

func (ffiObject *uniffiFfiObject) incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) unsafe.Pointer {
		return ffiObject.cloneFunction(ffiObject.pointer, status)
	})
}

func (ffiObject *uniffiFfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *uniffiFfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *uniffiFfiObject) freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}

// The same client with async methods: `await` them, they do not block the caller's thread.
type asyncPassboltClientInterface interface {
	// Add a resource to favorites.
	AddFavorite(resourceID string) (Favorite, error)
	// Add a tag to a resource, keeping its other tags; returns the resource's tags.
	AddTagToResource(resourceID string, slug string) ([]Tag, error)
	// Get the server base URL.
	BaseURL() string
	// Check if the session is still valid.
	CheckAuth() (bool, error)
	// Check if a password has been exposed in data breaches.
	// Returns the number of times found (0 = not breached).
	CheckPasswordPwned(password string) (uint64, error)
	// Create a comment on a resource.
	CreateComment(resourceID string, content string, parentID *string) (Comment, error)
	// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
	// parent's permissions.
	CreateFolder(name string, folderParentID *string) (Folder, error)
	// Create a group; a manager is also a member.
	CreateGroup(name string, memberIDs []string, managerIDs []string) (Group, error)
	// Create a resource of any type. Returns the created resource.
	CreateResource(resource NewResource) (Resource, error)
	// Create a user with the role named `role` (`user` or `admin`).
	CreateUser(username string, firstName string, lastName string, role string) (User, error)
	// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
	DecryptResourceSecret(resourceID string) (SecretData, error)
	// Delete a comment.
	DeleteComment(id string) error
	// Delete a folder; its content moves to the root.
	DeleteFolder(id string) error
	// Delete a folder with its sub-folders and the resources the user may delete in them.
	DeleteFolderWithContent(id string) error
	// Delete a group.
	DeleteGroup(id string) error
	// Preview the impact of deleting a group.
	DeleteGroupDryRun(id string) (GroupDeleteDryRun, error)
	// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
	// already has access to it.
	DeleteGroupWithTransfer(id string, successorID string) error
	// Delete the password expiry settings (admin): the defaults apply again.
	DeletePasswordExpirySettings(id string) error
	// Delete a resource.
	DeleteResource(id string) error
	// Bulk delete resources.
	DeleteResources(ids []string) error
	// Delete a tag.
	DeleteTag(id string) error
	// Delete a user.
	DeleteUser(id string) error
	// Preview the impact of deleting a user.
	DeleteUserDryRun(id string) (UserDeleteDryRun, error)
	// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
	// group that already has access to it.
	DeleteUserWithTransfer(id string, successorID string) error
	// Get comments for a resource.
	GetComments(resourceID string) ([]Comment, error)
	// Get a single folder by ID.
	GetFolder(id string) (Folder, error)
	// Get permissions for a folder.
	GetFolderPermissions(id string) ([]Permission, error)
	// Build a folder tree from the flat folder list.
	GetFolderTree() ([]FolderTreeNode, error)
	// Get a group by ID.
	GetGroup(id string) (Group, error)
	// Get the currently logged-in user.
	GetMe() (User, error)
	// How metadata keys are used in the organization.
	GetMetadataKeysSettings() (MetadataKeysSettings, error)
	// Which metadata versions the organization creates and allows.
	GetMetadataTypesSettings() (MetadataTypesSettings, error)
	// Get password expiry settings.
	GetPasswordExpirySettings() (PasswordExpirySettings, error)
	// The password policies of the organization, for [`generate_secret`].
	GetPasswordPolicies() (PasswordPolicies, error)
	// Get a single resource by ID.
	GetResource(id string) (Resource, error)
	// Get permissions for a resource.
	GetResourcePermissions(id string) ([]Permission, error)
	// A resource with its v5 metadata and its secret decrypted, for every resource type.
	GetResourceView(id string) (ResourceView, error)
	// Get multiple resources by IDs.
	GetResourcesByIDs(ids []string) ([]Resource, error)
	// List all tags.
	GetTags() ([]Tag, error)
	// Get a user by ID.
	GetUser(id string) (User, error)
	// What blocks deleting the group: what it alone owns.
	GroupDeleteBlockers(id string) (DeleteBlockers, error)
	// Keep the session alive, as the browser extension does every few minutes.
	KeepAlive() error
	// List all folders.
	listFolders(search *string) ([]Folder, error)
	// List all groups.
	ListGroups() ([]Group, error)
	// The resource types of the server.
	ListResourceTypes() ([]ResourceType, error)
	// Resources with their v5 metadata decrypted, searched by their decrypted name; their
	// secrets too with `with_secrets`. One that does not decrypt has an `error`.
	listResourceViews(search *string, withSecrets bool) ([]ResourceView, error)
	// List resources with optional search and filters.
	listResources(search *string, favoritesOnly bool, ownedByMe bool) ([]Resource, error)
	// List all users.
	listUsers(search *string, groupID *string, adminOnly bool) ([]User, error)
	// Terminate the server-side session.
	Logout() error
	// The fingerprint of the active shared metadata key, to pin in
	// [`LoginOptions::metadata_key_fingerprint`]; `None` without one.
	MetadataKeyFingerprint() (*string, error)
	// Move a folder into another one, or to the root without one.
	MoveFolder(id string, folderID *string) error
	// Move a resource into a folder, or to the root without one.
	MoveResource(id string, folderID *string) error
	// Remove a favorite.
	RemoveFavorite(favoriteID string) error
	// Rename a folder.
	RenameFolder(id string, name string) (Folder, error)
	// Rename a tag.
	RenameTag(id string, slug string) (Tag, error)
	// Save the metadata keys settings (admin).
	SaveMetadataKeysSettings(settings MetadataKeysSettings) (MetadataKeysSettings, error)
	// Save the metadata types settings (admin).
	SaveMetadataTypesSettings(settings MetadataTypesSettings) (MetadataTypesSettings, error)
	// Create or update the password expiry settings (admin).
	SavePasswordExpirySettings(settings PasswordExpirySettings) (PasswordExpirySettings, error)
	// Save the password policies of the organization (administrator, Passbolt Pro).
	SavePasswordPolicies(policies PasswordPolicies) (PasswordPolicies, error)
	// Search for users and groups (AROs) for sharing.
	SearchAros(search string) ([]Aro, error)
	// Replace all the tags of a resource; returns its tags.
	SetResourceTags(resourceID string, slugs []string) ([]Tag, error)
	// Share a folder, and with `with_content` the sub-folders and resources the user owns.
	shareFolder(id string, permissionType int32, userIDs []string, groupIDs []string, withContent bool) error
	// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
	shareResource(id string, permissionType int32, userIDs []string, groupIDs []string) error
	// Rename a group and change its members: the removed ones first, then the added ones,
	// who get the secrets of the group's resources. Giving a user the role they have, or
	// removing a non-member, is an error.
	updateGroup(id string, name *string, addMemberIDs []string, addManagerIDs []string, removeMemberIDs []string) (Group, error)
	// Update a resource; the fields left out keep their value.
	UpdateResource(id string, changes ResourceChanges) (Resource, error)
	// Update a user's names or role; `None` keeps the value.
	updateUser(id string, firstName *string, lastName *string, role *string) (User, error)
	// What blocks deleting the user: what they alone own or manage.
	UserDeleteBlockers(id string) (DeleteBlockers, error)
	// Get the current user's ID.
	UserID() string
}

// The same client with async methods: `await` them, they do not block the caller's thread.
type asyncPassboltClient struct {
	ffiObject uniffiFfiObject
}

// Authenticate against a Passbolt server and return a client session.
func asyncPassboltClientLogin(serverURL string, privateKeyArmored string, passphrase string) (*asyncPassboltClient, error) {
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_passbolt_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *asyncPassboltClient {
			return ffiConverterAsyncPassboltClientINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_constructor_asyncpassboltclient_login(ffiConverterStringINSTANCE.Lower(serverURL), ffiConverterStringINSTANCE.Lower(privateKeyArmored), ffiConverterStringINSTANCE.Lower(passphrase)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_pointer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Authenticate with `options`, the pinned server and metadata keys among them.
func asyncPassboltClientLoginWithConfig(serverURL string, privateKeyArmored string, passphrase string, options LoginOptions) (*asyncPassboltClient, error) {
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) unsafe.Pointer {
			res := C.ffi_passbolt_ffi_rust_future_complete_pointer(handle, status)
			return res
		},
		// liftFn
		func(ffi unsafe.Pointer) *asyncPassboltClient {
			return ffiConverterAsyncPassboltClientINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_constructor_asyncpassboltclient_login_with_config(ffiConverterStringINSTANCE.Lower(serverURL), ffiConverterStringINSTANCE.Lower(privateKeyArmored), ffiConverterStringINSTANCE.Lower(passphrase), ffiConverterLoginOptionsINSTANCE.Lower(options)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_pointer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_pointer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Add a resource to favorites.
func (_self *asyncPassboltClient) AddFavorite(resourceID string) (Favorite, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Favorite {
			return ffiConverterFavoriteINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_add_favorite(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Add a tag to a resource, keeping its other tags; returns the resource's tags.
func (_self *asyncPassboltClient) AddTagToResource(resourceID string, slug string) ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Tag {
			return ffiConverterSequenceTagINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_add_tag_to_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterStringINSTANCE.Lower(slug)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get the server base URL.
func (_self *asyncPassboltClient) BaseURL() string {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	return ffiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_base_url(
				_pointer, _uniffiStatus),
		}
	}))
}

// Check if the session is still valid.
func (_self *asyncPassboltClient) CheckAuth() (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) C.int8_t {
			res := C.ffi_passbolt_ffi_rust_future_complete_i8(handle, status)
			return res
		},
		// liftFn
		func(ffi C.int8_t) bool {
			return ffiConverterBoolINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_check_auth(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_i8(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_i8(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Check if a password has been exposed in data breaches.
// Returns the number of times found (0 = not breached).
func (_self *asyncPassboltClient) CheckPasswordPwned(password string) (uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
			res := C.ffi_passbolt_ffi_rust_future_complete_u64(handle, status)
			return res
		},
		// liftFn
		func(ffi C.uint64_t) uint64 {
			return ffiConverterUint64INSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_check_password_pwned(
			_pointer, ffiConverterStringINSTANCE.Lower(password)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_u64(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_u64(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create a comment on a resource.
func (_self *asyncPassboltClient) CreateComment(resourceID string, content string, parentID *string) (Comment, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Comment {
			return ffiConverterCommentINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_create_comment(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterStringINSTANCE.Lower(content), ffiConverterOptionalStringINSTANCE.Lower(parentID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
// parent's permissions.
func (_self *asyncPassboltClient) CreateFolder(name string, folderParentID *string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Folder {
			return ffiConverterFolderINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_create_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(name), ffiConverterOptionalStringINSTANCE.Lower(folderParentID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create a group; a manager is also a member.
func (_self *asyncPassboltClient) CreateGroup(name string, memberIDs []string, managerIDs []string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Group {
			return ffiConverterGroupINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_create_group(
			_pointer, ffiConverterStringINSTANCE.Lower(name), ffiConverterSequenceStringINSTANCE.Lower(memberIDs), ffiConverterSequenceStringINSTANCE.Lower(managerIDs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create a resource of any type. Returns the created resource.
func (_self *asyncPassboltClient) CreateResource(resource NewResource) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Resource {
			return ffiConverterResourceINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_create_resource(
			_pointer, ffiConverterNewResourceINSTANCE.Lower(resource)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create a user with the role named `role` (`user` or `admin`).
func (_self *asyncPassboltClient) CreateUser(username string, firstName string, lastName string, role string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) User {
			return ffiConverterUserINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_create_user(
			_pointer, ffiConverterStringINSTANCE.Lower(username), ffiConverterStringINSTANCE.Lower(firstName), ffiConverterStringINSTANCE.Lower(lastName), ffiConverterStringINSTANCE.Lower(role)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
func (_self *asyncPassboltClient) DecryptResourceSecret(resourceID string) (SecretData, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) SecretData {
			return ffiConverterSecretDataINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_decrypt_resource_secret(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Delete a comment.
func (_self *asyncPassboltClient) DeleteComment(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_comment(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a folder; its content moves to the root.
func (_self *asyncPassboltClient) DeleteFolder(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a folder with its sub-folders and the resources the user may delete in them.
func (_self *asyncPassboltClient) DeleteFolderWithContent(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_folder_with_content(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a group.
func (_self *asyncPassboltClient) DeleteGroup(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_group(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Preview the impact of deleting a group.
func (_self *asyncPassboltClient) DeleteGroupDryRun(id string) (GroupDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) GroupDeleteDryRun {
			return ffiConverterGroupDeleteDryRunINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_group_dry_run(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
// already has access to it.
func (_self *asyncPassboltClient) DeleteGroupWithTransfer(id string, successorID string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_group_with_transfer(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(successorID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete the password expiry settings (admin): the defaults apply again.
func (_self *asyncPassboltClient) DeletePasswordExpirySettings(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_password_expiry_settings(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a resource.
func (_self *asyncPassboltClient) DeleteResource(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Bulk delete resources.
func (_self *asyncPassboltClient) DeleteResources(ids []string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_resources(
			_pointer, ffiConverterSequenceStringINSTANCE.Lower(ids)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a tag.
func (_self *asyncPassboltClient) DeleteTag(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_tag(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Delete a user.
func (_self *asyncPassboltClient) DeleteUser(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_user(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Preview the impact of deleting a user.
func (_self *asyncPassboltClient) DeleteUserDryRun(id string) (UserDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) UserDeleteDryRun {
			return ffiConverterUserDeleteDryRunINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_user_dry_run(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
// group that already has access to it.
func (_self *asyncPassboltClient) DeleteUserWithTransfer(id string, successorID string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_delete_user_with_transfer(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(successorID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Get comments for a resource.
func (_self *asyncPassboltClient) GetComments(resourceID string) ([]Comment, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Comment {
			return ffiConverterSequenceCommentINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_comments(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get a single folder by ID.
func (_self *asyncPassboltClient) GetFolder(id string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Folder {
			return ffiConverterFolderINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get permissions for a folder.
func (_self *asyncPassboltClient) GetFolderPermissions(id string) ([]Permission, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Permission {
			return ffiConverterSequencePermissionINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_folder_permissions(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Build a folder tree from the flat folder list.
func (_self *asyncPassboltClient) GetFolderTree() ([]FolderTreeNode, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []FolderTreeNode {
			return ffiConverterSequenceFolderTreeNodeINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_folder_tree(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get a group by ID.
func (_self *asyncPassboltClient) GetGroup(id string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Group {
			return ffiConverterGroupINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_group(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get the currently logged-in user.
func (_self *asyncPassboltClient) GetMe() (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) User {
			return ffiConverterUserINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_me(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// How metadata keys are used in the organization.
func (_self *asyncPassboltClient) GetMetadataKeysSettings() (MetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) MetadataKeysSettings {
			return ffiConverterMetadataKeysSettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_metadata_keys_settings(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Which metadata versions the organization creates and allows.
func (_self *asyncPassboltClient) GetMetadataTypesSettings() (MetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) MetadataTypesSettings {
			return ffiConverterMetadataTypesSettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_metadata_types_settings(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get password expiry settings.
func (_self *asyncPassboltClient) GetPasswordExpirySettings() (PasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) PasswordExpirySettings {
			return ffiConverterPasswordExpirySettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_password_expiry_settings(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// The password policies of the organization, for [`generate_secret`].
func (_self *asyncPassboltClient) GetPasswordPolicies() (PasswordPolicies, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) PasswordPolicies {
			return ffiConverterPasswordPoliciesINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_password_policies(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get a single resource by ID.
func (_self *asyncPassboltClient) GetResource(id string) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Resource {
			return ffiConverterResourceINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get permissions for a resource.
func (_self *asyncPassboltClient) GetResourcePermissions(id string) ([]Permission, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Permission {
			return ffiConverterSequencePermissionINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_resource_permissions(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// A resource with its v5 metadata and its secret decrypted, for every resource type.
func (_self *asyncPassboltClient) GetResourceView(id string) (ResourceView, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) ResourceView {
			return ffiConverterResourceViewINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_resource_view(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get multiple resources by IDs.
func (_self *asyncPassboltClient) GetResourcesByIDs(ids []string) ([]Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Resource {
			return ffiConverterSequenceResourceINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_resources_by_ids(
			_pointer, ffiConverterSequenceStringINSTANCE.Lower(ids)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// List all tags.
func (_self *asyncPassboltClient) GetTags() ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Tag {
			return ffiConverterSequenceTagINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_tags(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get a user by ID.
func (_self *asyncPassboltClient) GetUser(id string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) User {
			return ffiConverterUserINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_get_user(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// What blocks deleting the group: what it alone owns.
func (_self *asyncPassboltClient) GroupDeleteBlockers(id string) (DeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) DeleteBlockers {
			return ffiConverterDeleteBlockersINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_group_delete_blockers(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Keep the session alive, as the browser extension does every few minutes.
func (_self *asyncPassboltClient) KeepAlive() error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_keep_alive(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// List all folders.
func (_self *asyncPassboltClient) listFolders(search *string) ([]Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Folder {
			return ffiConverterSequenceFolderINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_folders(
			_pointer, ffiConverterOptionalStringINSTANCE.Lower(search)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// List all groups.
func (_self *asyncPassboltClient) ListGroups() ([]Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Group {
			return ffiConverterSequenceGroupINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_groups(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// The resource types of the server.
func (_self *asyncPassboltClient) ListResourceTypes() ([]ResourceType, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []ResourceType {
			return ffiConverterSequenceResourceTypeINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_resource_types(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Resources with their v5 metadata decrypted, searched by their decrypted name; their
// secrets too with `with_secrets`. One that does not decrypt has an `error`.
func (_self *asyncPassboltClient) listResourceViews(search *string, withSecrets bool) ([]ResourceView, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []ResourceView {
			return ffiConverterSequenceResourceViewINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_resource_views(
			_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterBoolINSTANCE.Lower(withSecrets)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// List resources with optional search and filters.
func (_self *asyncPassboltClient) listResources(search *string, favoritesOnly bool, ownedByMe bool) ([]Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Resource {
			return ffiConverterSequenceResourceINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_resources(
			_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterBoolINSTANCE.Lower(favoritesOnly), ffiConverterBoolINSTANCE.Lower(ownedByMe)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// List all users.
func (_self *asyncPassboltClient) listUsers(search *string, groupID *string, adminOnly bool) ([]User, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []User {
			return ffiConverterSequenceUserINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_list_users(
			_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterOptionalStringINSTANCE.Lower(groupID), ffiConverterBoolINSTANCE.Lower(adminOnly)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Terminate the server-side session.
func (_self *asyncPassboltClient) Logout() error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_logout(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// The fingerprint of the active shared metadata key, to pin in
// [`LoginOptions::metadata_key_fingerprint`]; `None` without one.
func (_self *asyncPassboltClient) MetadataKeyFingerprint() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) *string {
			return ffiConverterOptionalStringINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_metadata_key_fingerprint(
			_pointer),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Move a folder into another one, or to the root without one.
func (_self *asyncPassboltClient) MoveFolder(id string, folderID *string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_move_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(folderID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Move a resource into a folder, or to the root without one.
func (_self *asyncPassboltClient) MoveResource(id string, folderID *string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_move_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(folderID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Remove a favorite.
func (_self *asyncPassboltClient) RemoveFavorite(favoriteID string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_remove_favorite(
			_pointer, ffiConverterStringINSTANCE.Lower(favoriteID)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Rename a folder.
func (_self *asyncPassboltClient) RenameFolder(id string, name string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Folder {
			return ffiConverterFolderINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_rename_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(name)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Rename a tag.
func (_self *asyncPassboltClient) RenameTag(id string, slug string) (Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Tag {
			return ffiConverterTagINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_rename_tag(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(slug)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Save the metadata keys settings (admin).
func (_self *asyncPassboltClient) SaveMetadataKeysSettings(settings MetadataKeysSettings) (MetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) MetadataKeysSettings {
			return ffiConverterMetadataKeysSettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_save_metadata_keys_settings(
			_pointer, ffiConverterMetadataKeysSettingsINSTANCE.Lower(settings)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Save the metadata types settings (admin).
func (_self *asyncPassboltClient) SaveMetadataTypesSettings(settings MetadataTypesSettings) (MetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) MetadataTypesSettings {
			return ffiConverterMetadataTypesSettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_save_metadata_types_settings(
			_pointer, ffiConverterMetadataTypesSettingsINSTANCE.Lower(settings)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Create or update the password expiry settings (admin).
func (_self *asyncPassboltClient) SavePasswordExpirySettings(settings PasswordExpirySettings) (PasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) PasswordExpirySettings {
			return ffiConverterPasswordExpirySettingsINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_save_password_expiry_settings(
			_pointer, ffiConverterPasswordExpirySettingsINSTANCE.Lower(settings)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Save the password policies of the organization (administrator, Passbolt Pro).
func (_self *asyncPassboltClient) SavePasswordPolicies(policies PasswordPolicies) (PasswordPolicies, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) PasswordPolicies {
			return ffiConverterPasswordPoliciesINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_save_password_policies(
			_pointer, ffiConverterPasswordPoliciesINSTANCE.Lower(policies)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Search for users and groups (AROs) for sharing.
func (_self *asyncPassboltClient) SearchAros(search string) ([]Aro, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Aro {
			return ffiConverterSequenceAroINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_search_aros(
			_pointer, ffiConverterStringINSTANCE.Lower(search)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Replace all the tags of a resource; returns its tags.
func (_self *asyncPassboltClient) SetResourceTags(resourceID string, slugs []string) ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) []Tag {
			return ffiConverterSequenceTagINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_set_resource_tags(
			_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterSequenceStringINSTANCE.Lower(slugs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Share a folder, and with `with_content` the sub-folders and resources the user owns.
func (_self *asyncPassboltClient) shareFolder(id string, permissionType int32, userIDs []string, groupIDs []string, withContent bool) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_share_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterInt32INSTANCE.Lower(permissionType), ffiConverterSequenceStringINSTANCE.Lower(userIDs), ffiConverterSequenceStringINSTANCE.Lower(groupIDs), ffiConverterBoolINSTANCE.Lower(withContent)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
func (_self *asyncPassboltClient) shareResource(id string, permissionType int32, userIDs []string, groupIDs []string) error {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) struct{} {
			C.ffi_passbolt_ffi_rust_future_complete_void(handle, status)
			return struct{}{}
		},
		// liftFn
		func(_ struct{}) struct{} { return struct{}{} },
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_share_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterInt32INSTANCE.Lower(permissionType), ffiConverterSequenceStringINSTANCE.Lower(userIDs), ffiConverterSequenceStringINSTANCE.Lower(groupIDs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_void(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_void(handle)
		},
	)

	if err == nil {
		return nil
	}

	return err
}

// Rename a group and change its members: the removed ones first, then the added ones,
// who get the secrets of the group's resources. Giving a user the role they have, or
// removing a non-member, is an error.
func (_self *asyncPassboltClient) updateGroup(id string, name *string, addMemberIDs []string, addManagerIDs []string, removeMemberIDs []string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Group {
			return ffiConverterGroupINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_update_group(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(name), ffiConverterSequenceStringINSTANCE.Lower(addMemberIDs), ffiConverterSequenceStringINSTANCE.Lower(addManagerIDs), ffiConverterSequenceStringINSTANCE.Lower(removeMemberIDs)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Update a resource; the fields left out keep their value.
func (_self *asyncPassboltClient) UpdateResource(id string, changes ResourceChanges) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) Resource {
			return ffiConverterResourceINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_update_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterResourceChangesINSTANCE.Lower(changes)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Update a user's names or role; `None` keeps the value.
func (_self *asyncPassboltClient) updateUser(id string, firstName *string, lastName *string, role *string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) User {
			return ffiConverterUserINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_update_user(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(firstName), ffiConverterOptionalStringINSTANCE.Lower(lastName), ffiConverterOptionalStringINSTANCE.Lower(role)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// What blocks deleting the user: what they alone own or manage.
func (_self *asyncPassboltClient) UserDeleteBlockers(id string) (DeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	res, err := uniffiRustCallAsync[PassboltError](
		ffiConverterPassboltErrorINSTANCE,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) rustBufferI {
			res := C.ffi_passbolt_ffi_rust_future_complete_rust_buffer(handle, status)
			return goRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi rustBufferI) DeleteBlockers {
			return ffiConverterDeleteBlockersINSTANCE.Lift(ffi)
		},
		C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_user_delete_blockers(
			_pointer, ffiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_passbolt_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	if err == nil {
		return res, nil
	}

	return res, err
}

// Get the current user's ID.
func (_self *asyncPassboltClient) UserID() string {
	_pointer := _self.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer _self.ffiObject.decrementPointer()
	return ffiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_asyncpassboltclient_user_id(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *asyncPassboltClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type ffiConverterAsyncPassboltClient struct{}

var ffiConverterAsyncPassboltClientINSTANCE = ffiConverterAsyncPassboltClient{}

func (c ffiConverterAsyncPassboltClient) Lift(pointer unsafe.Pointer) *asyncPassboltClient {
	result := &asyncPassboltClient{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_passbolt_ffi_fn_clone_asyncpassboltclient(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_passbolt_ffi_fn_free_asyncpassboltclient(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*asyncPassboltClient).Destroy)
	return result
}

func (c ffiConverterAsyncPassboltClient) Read(reader io.Reader) *asyncPassboltClient {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c ffiConverterAsyncPassboltClient) Lower(value *asyncPassboltClient) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*AsyncPassboltClient")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c ffiConverterAsyncPassboltClient) Write(writer io.Writer, value *asyncPassboltClient) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type ffiDestroyerAsyncPassboltClient struct{}

func (_ ffiDestroyerAsyncPassboltClient) Destroy(value *asyncPassboltClient) {
	value.Destroy()
}

// Authenticated Passbolt client for CRUD operations.
//
// All methods are synchronous at the FFI boundary; they block internally
// on the tokio runtime. Call from background threads on mobile platforms, or use
// [`AsyncPassboltClient`].
type passboltClientInterface interface {
	// Add a resource to favorites.
	AddFavorite(resourceID string) (Favorite, error)
	// Add a tag to a resource, keeping its other tags; returns the resource's tags.
	AddTagToResource(resourceID string, slug string) ([]Tag, error)
	// Get the server base URL.
	BaseURL() string
	// Check if the session is still valid.
	CheckAuth() (bool, error)
	// Check if a password has been exposed in data breaches.
	// Returns the number of times found (0 = not breached).
	CheckPasswordPwned(password string) (uint64, error)
	// Create a comment on a resource.
	CreateComment(resourceID string, content string, parentID *string) (Comment, error)
	// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
	// parent's permissions.
	CreateFolder(name string, folderParentID *string) (Folder, error)
	// Create a group; a manager is also a member.
	CreateGroup(name string, memberIDs []string, managerIDs []string) (Group, error)
	// Create a resource of any type. Returns the created resource.
	CreateResource(resource NewResource) (Resource, error)
	// Create a user with the role named `role` (`user` or `admin`).
	CreateUser(username string, firstName string, lastName string, role string) (User, error)
	// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
	DecryptResourceSecret(resourceID string) (SecretData, error)
	// Delete a comment.
	DeleteComment(id string) error
	// Delete a folder; its content moves to the root.
	DeleteFolder(id string) error
	// Delete a folder with its sub-folders and the resources the user may delete in them.
	DeleteFolderWithContent(id string) error
	// Delete a group.
	DeleteGroup(id string) error
	// Preview the impact of deleting a group.
	DeleteGroupDryRun(id string) (GroupDeleteDryRun, error)
	// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
	// already has access to it.
	DeleteGroupWithTransfer(id string, successorID string) error
	// Delete the password expiry settings (admin): the defaults apply again.
	DeletePasswordExpirySettings(id string) error
	// Delete a resource.
	DeleteResource(id string) error
	// Bulk delete resources.
	DeleteResources(ids []string) error
	// Delete a tag.
	DeleteTag(id string) error
	// Delete a user.
	DeleteUser(id string) error
	// Preview the impact of deleting a user.
	DeleteUserDryRun(id string) (UserDeleteDryRun, error)
	// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
	// group that already has access to it.
	DeleteUserWithTransfer(id string, successorID string) error
	// Get comments for a resource.
	GetComments(resourceID string) ([]Comment, error)
	// Get a single folder by ID.
	GetFolder(id string) (Folder, error)
	// Get permissions for a folder.
	GetFolderPermissions(id string) ([]Permission, error)
	// Build a folder tree from the flat folder list.
	GetFolderTree() ([]FolderTreeNode, error)
	// Get a group by ID.
	GetGroup(id string) (Group, error)
	// Get the currently logged-in user.
	GetMe() (User, error)
	// How metadata keys are used in the organization.
	GetMetadataKeysSettings() (MetadataKeysSettings, error)
	// Which metadata versions the organization creates and allows.
	GetMetadataTypesSettings() (MetadataTypesSettings, error)
	// Get password expiry settings.
	GetPasswordExpirySettings() (PasswordExpirySettings, error)
	// The password policies of the organization, for [`generate_secret`].
	GetPasswordPolicies() (PasswordPolicies, error)
	// Get a single resource by ID.
	GetResource(id string) (Resource, error)
	// Get permissions for a resource.
	GetResourcePermissions(id string) ([]Permission, error)
	// A resource with its v5 metadata and its secret decrypted, for every resource type.
	GetResourceView(id string) (ResourceView, error)
	// Get multiple resources by IDs.
	GetResourcesByIDs(ids []string) ([]Resource, error)
	// List all tags.
	GetTags() ([]Tag, error)
	// Get a user by ID.
	GetUser(id string) (User, error)
	// What blocks deleting the group: what it alone owns.
	GroupDeleteBlockers(id string) (DeleteBlockers, error)
	// Keep the session alive, as the browser extension does every few minutes.
	KeepAlive() error
	// List all folders.
	listFolders(search *string) ([]Folder, error)
	// List all groups.
	ListGroups() ([]Group, error)
	// The resource types of the server.
	ListResourceTypes() ([]ResourceType, error)
	// Resources with their v5 metadata decrypted, searched by their decrypted name; their
	// secrets too with `with_secrets`. One that does not decrypt has an `error`.
	listResourceViews(search *string, withSecrets bool) ([]ResourceView, error)
	// List resources with optional search and filters.
	listResources(search *string, favoritesOnly bool, ownedByMe bool) ([]Resource, error)
	// List all users.
	listUsers(search *string, groupID *string, adminOnly bool) ([]User, error)
	// Terminate the server-side session.
	Logout() error
	// The fingerprint of the active shared metadata key, to pin in
	// [`LoginOptions::metadata_key_fingerprint`]; `None` without one.
	MetadataKeyFingerprint() (*string, error)
	// Move a folder into another one, or to the root without one.
	MoveFolder(id string, folderID *string) error
	// Move a resource into a folder, or to the root without one.
	MoveResource(id string, folderID *string) error
	// Remove a favorite.
	RemoveFavorite(favoriteID string) error
	// Rename a folder.
	RenameFolder(id string, name string) (Folder, error)
	// Rename a tag.
	RenameTag(id string, slug string) (Tag, error)
	// Save the metadata keys settings (admin).
	SaveMetadataKeysSettings(settings MetadataKeysSettings) (MetadataKeysSettings, error)
	// Save the metadata types settings (admin).
	SaveMetadataTypesSettings(settings MetadataTypesSettings) (MetadataTypesSettings, error)
	// Create or update the password expiry settings (admin).
	SavePasswordExpirySettings(settings PasswordExpirySettings) (PasswordExpirySettings, error)
	// Save the password policies of the organization (administrator, Passbolt Pro).
	SavePasswordPolicies(policies PasswordPolicies) (PasswordPolicies, error)
	// Search for users and groups (AROs) for sharing.
	SearchAros(search string) ([]Aro, error)
	// Replace all the tags of a resource; returns its tags.
	SetResourceTags(resourceID string, slugs []string) ([]Tag, error)
	// Share a folder, and with `with_content` the sub-folders and resources the user owns.
	shareFolder(id string, permissionType int32, userIDs []string, groupIDs []string, withContent bool) error
	// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
	shareResource(id string, permissionType int32, userIDs []string, groupIDs []string) error
	// Rename a group and change its members: the removed ones first, then the added ones,
	// who get the secrets of the group's resources. Giving a user the role they have, or
	// removing a non-member, is an error.
	updateGroup(id string, name *string, addMemberIDs []string, addManagerIDs []string, removeMemberIDs []string) (Group, error)
	// Update a resource; the fields left out keep their value.
	UpdateResource(id string, changes ResourceChanges) (Resource, error)
	// Update a user's names or role; `None` keeps the value.
	updateUser(id string, firstName *string, lastName *string, role *string) (User, error)
	// What blocks deleting the user: what they alone own or manage.
	UserDeleteBlockers(id string) (DeleteBlockers, error)
	// Get the current user's ID.
	UserID() string
}

// Authenticated Passbolt client for CRUD operations.
//
// All methods are synchronous at the FFI boundary; they block internally
// on the tokio runtime. Call from background threads on mobile platforms, or use
// [`AsyncPassboltClient`].
type PassboltClient struct {
	ffiObject uniffiFfiObject
}

// Authenticate against a Passbolt server and return a client session.
func PassboltClientLogin(serverURL string, privateKeyArmored string, passphrase string) (*PassboltClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_passbolt_ffi_fn_constructor_passboltclient_login(ffiConverterStringINSTANCE.Lower(serverURL), ffiConverterStringINSTANCE.Lower(privateKeyArmored), ffiConverterStringINSTANCE.Lower(passphrase), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *PassboltClient
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPassboltClientINSTANCE.Lift(_uniffiRV), nil
	}
}

// Authenticate with `options`, the pinned server and metadata keys among them.
func PassboltClientLoginWithConfig(serverURL string, privateKeyArmored string, passphrase string, options LoginOptions) (*PassboltClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_passbolt_ffi_fn_constructor_passboltclient_login_with_config(ffiConverterStringINSTANCE.Lower(serverURL), ffiConverterStringINSTANCE.Lower(privateKeyArmored), ffiConverterStringINSTANCE.Lower(passphrase), ffiConverterLoginOptionsINSTANCE.Lower(options), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *PassboltClient
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPassboltClientINSTANCE.Lift(_uniffiRV), nil
	}
}

// Add a resource to favorites.
func (_self *PassboltClient) AddFavorite(resourceID string) (Favorite, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_add_favorite(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Favorite
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterFavoriteINSTANCE.Lift(_uniffiRV), nil
	}
}

// Add a tag to a resource, keeping its other tags; returns the resource's tags.
func (_self *PassboltClient) AddTagToResource(resourceID string, slug string) ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_add_tag_to_resource(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterStringINSTANCE.Lower(slug), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Tag
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceTagINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get the server base URL.
func (_self *PassboltClient) BaseURL() string {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	return ffiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_base_url(
				_pointer, _uniffiStatus),
		}
	}))
}

// Check if the session is still valid.
func (_self *PassboltClient) CheckAuth() (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_passbolt_ffi_fn_method_passboltclient_check_auth(
			_pointer, _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

// Check if a password has been exposed in data breaches.
// Returns the number of times found (0 = not breached).
func (_self *PassboltClient) CheckPasswordPwned(password string) (uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_passbolt_ffi_fn_method_passboltclient_check_password_pwned(
			_pointer, ffiConverterStringINSTANCE.Lower(password), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue uint64
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUint64INSTANCE.Lift(_uniffiRV), nil
	}
}

// Create a comment on a resource.
func (_self *PassboltClient) CreateComment(resourceID string, content string, parentID *string) (Comment, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_comment(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterStringINSTANCE.Lower(content), ffiConverterOptionalStringINSTANCE.Lower(parentID), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Comment
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterCommentINSTANCE.Lift(_uniffiRV), nil
	}
}

// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
// parent's permissions.
func (_self *PassboltClient) CreateFolder(name string, folderParentID *string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_folder(
				_pointer, ffiConverterStringINSTANCE.Lower(name), ffiConverterOptionalStringINSTANCE.Lower(folderParentID), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Folder
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterFolderINSTANCE.Lift(_uniffiRV), nil
	}
}

// Create a group; a manager is also a member.
func (_self *PassboltClient) CreateGroup(name string, memberIDs []string, managerIDs []string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_group(
				_pointer, ffiConverterStringINSTANCE.Lower(name), ffiConverterSequenceStringINSTANCE.Lower(memberIDs), ffiConverterSequenceStringINSTANCE.Lower(managerIDs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Group
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterGroupINSTANCE.Lift(_uniffiRV), nil
	}
}

// Create a resource of any type. Returns the created resource.
func (_self *PassboltClient) CreateResource(resource NewResource) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_resource(
				_pointer, ffiConverterNewResourceINSTANCE.Lower(resource), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Resource
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterResourceINSTANCE.Lift(_uniffiRV), nil
	}
}

// Create a user with the role named `role` (`user` or `admin`).
func (_self *PassboltClient) CreateUser(username string, firstName string, lastName string, role string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_user(
				_pointer, ffiConverterStringINSTANCE.Lower(username), ffiConverterStringINSTANCE.Lower(firstName), ffiConverterStringINSTANCE.Lower(lastName), ffiConverterStringINSTANCE.Lower(role), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue User
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUserINSTANCE.Lift(_uniffiRV), nil
	}
}

// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
func (_self *PassboltClient) DecryptResourceSecret(resourceID string) (SecretData, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_decrypt_resource_secret(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue SecretData
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSecretDataINSTANCE.Lift(_uniffiRV), nil
	}
}

// Delete a comment.
func (_self *PassboltClient) DeleteComment(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_comment(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a folder; its content moves to the root.
func (_self *PassboltClient) DeleteFolder(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a folder with its sub-folders and the resources the user may delete in them.
func (_self *PassboltClient) DeleteFolderWithContent(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_folder_with_content(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a group.
func (_self *PassboltClient) DeleteGroup(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Preview the impact of deleting a group.
func (_self *PassboltClient) DeleteGroupDryRun(id string) (GroupDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group_dry_run(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue GroupDeleteDryRun
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterGroupDeleteDryRunINSTANCE.Lift(_uniffiRV), nil
	}
}

// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
// already has access to it.
func (_self *PassboltClient) DeleteGroupWithTransfer(id string, successorID string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group_with_transfer(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(successorID), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete the password expiry settings (admin): the defaults apply again.
func (_self *PassboltClient) DeletePasswordExpirySettings(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_password_expiry_settings(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a resource.
func (_self *PassboltClient) DeleteResource(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Bulk delete resources.
func (_self *PassboltClient) DeleteResources(ids []string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_resources(
			_pointer, ffiConverterSequenceStringINSTANCE.Lower(ids), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a tag.
func (_self *PassboltClient) DeleteTag(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_tag(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Delete a user.
func (_self *PassboltClient) DeleteUser(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user(
			_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Preview the impact of deleting a user.
func (_self *PassboltClient) DeleteUserDryRun(id string) (UserDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user_dry_run(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue UserDeleteDryRun
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUserDeleteDryRunINSTANCE.Lift(_uniffiRV), nil
	}
}

// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
// group that already has access to it.
func (_self *PassboltClient) DeleteUserWithTransfer(id string, successorID string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user_with_transfer(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(successorID), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Get comments for a resource.
func (_self *PassboltClient) GetComments(resourceID string) ([]Comment, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_comments(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Comment
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceCommentINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get a single folder by ID.
func (_self *PassboltClient) GetFolder(id string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Folder
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterFolderINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get permissions for a folder.
func (_self *PassboltClient) GetFolderPermissions(id string) ([]Permission, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder_permissions(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Permission
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequencePermissionINSTANCE.Lift(_uniffiRV), nil
	}
}

// Build a folder tree from the flat folder list.
func (_self *PassboltClient) GetFolderTree() ([]FolderTreeNode, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder_tree(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []FolderTreeNode
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceFolderTreeNodeINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get a group by ID.
func (_self *PassboltClient) GetGroup(id string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_group(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Group
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterGroupINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get the currently logged-in user.
func (_self *PassboltClient) GetMe() (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_me(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue User
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUserINSTANCE.Lift(_uniffiRV), nil
	}
}

// How metadata keys are used in the organization.
func (_self *PassboltClient) GetMetadataKeysSettings() (MetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_metadata_keys_settings(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue MetadataKeysSettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterMetadataKeysSettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// Which metadata versions the organization creates and allows.
func (_self *PassboltClient) GetMetadataTypesSettings() (MetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_metadata_types_settings(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue MetadataTypesSettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterMetadataTypesSettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get password expiry settings.
func (_self *PassboltClient) GetPasswordExpirySettings() (PasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_password_expiry_settings(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PasswordExpirySettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPasswordExpirySettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// The password policies of the organization, for [`generate_secret`].
func (_self *PassboltClient) GetPasswordPolicies() (PasswordPolicies, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_password_policies(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PasswordPolicies
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPasswordPoliciesINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get a single resource by ID.
func (_self *PassboltClient) GetResource(id string) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Resource
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterResourceINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get permissions for a resource.
func (_self *PassboltClient) GetResourcePermissions(id string) ([]Permission, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource_permissions(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Permission
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequencePermissionINSTANCE.Lift(_uniffiRV), nil
	}
}

// A resource with its v5 metadata and its secret decrypted, for every resource type.
func (_self *PassboltClient) GetResourceView(id string) (ResourceView, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource_view(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ResourceView
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterResourceViewINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get multiple resources by IDs.
func (_self *PassboltClient) GetResourcesByIDs(ids []string) ([]Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resources_by_ids(
				_pointer, ffiConverterSequenceStringINSTANCE.Lower(ids), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Resource
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceResourceINSTANCE.Lift(_uniffiRV), nil
	}
}

// List all tags.
func (_self *PassboltClient) GetTags() ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_tags(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Tag
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceTagINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get a user by ID.
func (_self *PassboltClient) GetUser(id string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_user(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue User
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUserINSTANCE.Lift(_uniffiRV), nil
	}
}

// What blocks deleting the group: what it alone owns.
func (_self *PassboltClient) GroupDeleteBlockers(id string) (DeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_group_delete_blockers(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue DeleteBlockers
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterDeleteBlockersINSTANCE.Lift(_uniffiRV), nil
	}
}

// Keep the session alive, as the browser extension does every few minutes.
func (_self *PassboltClient) KeepAlive() error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_keep_alive(
			_pointer, _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// List all folders.
func (_self *PassboltClient) listFolders(search *string) ([]Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_folders(
				_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Folder
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceFolderINSTANCE.Lift(_uniffiRV), nil
	}
}

// List all groups.
func (_self *PassboltClient) ListGroups() ([]Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_groups(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Group
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceGroupINSTANCE.Lift(_uniffiRV), nil
	}
}

// The resource types of the server.
func (_self *PassboltClient) ListResourceTypes() ([]ResourceType, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resource_types(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []ResourceType
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceResourceTypeINSTANCE.Lift(_uniffiRV), nil
	}
}

// Resources with their v5 metadata decrypted, searched by their decrypted name; their
// secrets too with `with_secrets`. One that does not decrypt has an `error`.
func (_self *PassboltClient) listResourceViews(search *string, withSecrets bool) ([]ResourceView, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resource_views(
				_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterBoolINSTANCE.Lower(withSecrets), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []ResourceView
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceResourceViewINSTANCE.Lift(_uniffiRV), nil
	}
}

// List resources with optional search and filters.
func (_self *PassboltClient) listResources(search *string, favoritesOnly bool, ownedByMe bool) ([]Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resources(
				_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterBoolINSTANCE.Lower(favoritesOnly), ffiConverterBoolINSTANCE.Lower(ownedByMe), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Resource
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceResourceINSTANCE.Lift(_uniffiRV), nil
	}
}

// List all users.
func (_self *PassboltClient) listUsers(search *string, groupID *string, adminOnly bool) ([]User, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_users(
				_pointer, ffiConverterOptionalStringINSTANCE.Lower(search), ffiConverterOptionalStringINSTANCE.Lower(groupID), ffiConverterBoolINSTANCE.Lower(adminOnly), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []User
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceUserINSTANCE.Lift(_uniffiRV), nil
	}
}

// Terminate the server-side session.
func (_self *PassboltClient) Logout() error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_logout(
			_pointer, _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// The fingerprint of the active shared metadata key, to pin in
// [`LoginOptions::metadata_key_fingerprint`]; `None` without one.
func (_self *PassboltClient) MetadataKeyFingerprint() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_metadata_key_fingerprint(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterOptionalStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Move a folder into another one, or to the root without one.
func (_self *PassboltClient) MoveFolder(id string, folderID *string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_move_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(folderID), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Move a resource into a folder, or to the root without one.
func (_self *PassboltClient) MoveResource(id string, folderID *string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_move_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(folderID), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Remove a favorite.
func (_self *PassboltClient) RemoveFavorite(favoriteID string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_remove_favorite(
			_pointer, ffiConverterStringINSTANCE.Lower(favoriteID), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Rename a folder.
func (_self *PassboltClient) RenameFolder(id string, name string) (Folder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_rename_folder(
				_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(name), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Folder
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterFolderINSTANCE.Lift(_uniffiRV), nil
	}
}

// Rename a tag.
func (_self *PassboltClient) RenameTag(id string, slug string) (Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_rename_tag(
				_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterStringINSTANCE.Lower(slug), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Tag
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterTagINSTANCE.Lift(_uniffiRV), nil
	}
}

// Save the metadata keys settings (admin).
func (_self *PassboltClient) SaveMetadataKeysSettings(settings MetadataKeysSettings) (MetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_metadata_keys_settings(
				_pointer, ffiConverterMetadataKeysSettingsINSTANCE.Lower(settings), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue MetadataKeysSettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterMetadataKeysSettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// Save the metadata types settings (admin).
func (_self *PassboltClient) SaveMetadataTypesSettings(settings MetadataTypesSettings) (MetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_metadata_types_settings(
				_pointer, ffiConverterMetadataTypesSettingsINSTANCE.Lower(settings), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue MetadataTypesSettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterMetadataTypesSettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// Create or update the password expiry settings (admin).
func (_self *PassboltClient) SavePasswordExpirySettings(settings PasswordExpirySettings) (PasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_password_expiry_settings(
				_pointer, ffiConverterPasswordExpirySettingsINSTANCE.Lower(settings), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PasswordExpirySettings
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPasswordExpirySettingsINSTANCE.Lift(_uniffiRV), nil
	}
}

// Save the password policies of the organization (administrator, Passbolt Pro).
func (_self *PassboltClient) SavePasswordPolicies(policies PasswordPolicies) (PasswordPolicies, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_password_policies(
				_pointer, ffiConverterPasswordPoliciesINSTANCE.Lower(policies), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PasswordPolicies
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterPasswordPoliciesINSTANCE.Lift(_uniffiRV), nil
	}
}

// Search for users and groups (AROs) for sharing.
func (_self *PassboltClient) SearchAros(search string) ([]Aro, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_search_aros(
				_pointer, ffiConverterStringINSTANCE.Lower(search), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Aro
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceAroINSTANCE.Lift(_uniffiRV), nil
	}
}

// Replace all the tags of a resource; returns its tags.
func (_self *PassboltClient) SetResourceTags(resourceID string, slugs []string) ([]Tag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_set_resource_tags(
				_pointer, ffiConverterStringINSTANCE.Lower(resourceID), ffiConverterSequenceStringINSTANCE.Lower(slugs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Tag
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterSequenceTagINSTANCE.Lift(_uniffiRV), nil
	}
}

// Share a folder, and with `with_content` the sub-folders and resources the user owns.
func (_self *PassboltClient) shareFolder(id string, permissionType int32, userIDs []string, groupIDs []string, withContent bool) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_share_folder(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterInt32INSTANCE.Lower(permissionType), ffiConverterSequenceStringINSTANCE.Lower(userIDs), ffiConverterSequenceStringINSTANCE.Lower(groupIDs), ffiConverterBoolINSTANCE.Lower(withContent), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
func (_self *PassboltClient) shareResource(id string, permissionType int32, userIDs []string, groupIDs []string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_share_resource(
			_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterInt32INSTANCE.Lower(permissionType), ffiConverterSequenceStringINSTANCE.Lower(userIDs), ffiConverterSequenceStringINSTANCE.Lower(groupIDs), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

// Rename a group and change its members: the removed ones first, then the added ones,
// who get the secrets of the group's resources. Giving a user the role they have, or
// removing a non-member, is an error.
func (_self *PassboltClient) updateGroup(id string, name *string, addMemberIDs []string, addManagerIDs []string, removeMemberIDs []string) (Group, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_group(
				_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(name), ffiConverterSequenceStringINSTANCE.Lower(addMemberIDs), ffiConverterSequenceStringINSTANCE.Lower(addManagerIDs), ffiConverterSequenceStringINSTANCE.Lower(removeMemberIDs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Group
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterGroupINSTANCE.Lift(_uniffiRV), nil
	}
}

// Update a resource; the fields left out keep their value.
func (_self *PassboltClient) UpdateResource(id string, changes ResourceChanges) (Resource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_resource(
				_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterResourceChangesINSTANCE.Lower(changes), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Resource
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterResourceINSTANCE.Lift(_uniffiRV), nil
	}
}

// Update a user's names or role; `None` keeps the value.
func (_self *PassboltClient) updateUser(id string, firstName *string, lastName *string, role *string) (User, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_user(
				_pointer, ffiConverterStringINSTANCE.Lower(id), ffiConverterOptionalStringINSTANCE.Lower(firstName), ffiConverterOptionalStringINSTANCE.Lower(lastName), ffiConverterOptionalStringINSTANCE.Lower(role), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue User
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterUserINSTANCE.Lift(_uniffiRV), nil
	}
}

// What blocks deleting the user: what they alone own or manage.
func (_self *PassboltClient) UserDeleteBlockers(id string) (DeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_user_delete_blockers(
				_pointer, ffiConverterStringINSTANCE.Lower(id), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue DeleteBlockers
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterDeleteBlockersINSTANCE.Lift(_uniffiRV), nil
	}
}

// Get the current user's ID.
func (_self *PassboltClient) UserID() string {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	return ffiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_user_id(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *PassboltClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type ffiConverterPassboltClient struct{}

var ffiConverterPassboltClientINSTANCE = ffiConverterPassboltClient{}

func (c ffiConverterPassboltClient) Lift(pointer unsafe.Pointer) *PassboltClient {
	result := &PassboltClient{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) unsafe.Pointer {
				return C.uniffi_passbolt_ffi_fn_clone_passboltclient(pointer, status)
			},
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_passbolt_ffi_fn_free_passboltclient(pointer, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*PassboltClient).Destroy)
	return result
}

func (c ffiConverterPassboltClient) Read(reader io.Reader) *PassboltClient {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c ffiConverterPassboltClient) Lower(value *PassboltClient) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*PassboltClient")
	defer value.ffiObject.decrementPointer()
	return pointer

}

func (c ffiConverterPassboltClient) Write(writer io.Writer, value *PassboltClient) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type ffiDestroyerPassboltClient struct{}

func (_ ffiDestroyerPassboltClient) Destroy(value *PassboltClient) {
	value.Destroy()
}

type Aro struct {
	ID       string
	AroType  *string
	Username *string
	Profile  *UserProfile
	Name     *string
}

func (r *Aro) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.AroType)
	ffiDestroyerOptionalString{}.Destroy(r.Username)
	ffiDestroyerOptionalUserProfile{}.Destroy(r.Profile)
	ffiDestroyerOptionalString{}.Destroy(r.Name)
}

type ffiConverterAro struct{}

var ffiConverterAroINSTANCE = ffiConverterAro{}

func (c ffiConverterAro) Lift(rb rustBufferI) Aro {
	return liftFromRustBuffer[Aro](c, rb)
}

func (c ffiConverterAro) Read(reader io.Reader) Aro {
	return Aro{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUserProfileINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterAro) Lower(value Aro) C.RustBuffer {
	return lowerIntoRustBuffer[Aro](c, value)
}

func (c ffiConverterAro) LowerExternal(value Aro) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Aro](c, value))
}

func (c ffiConverterAro) Write(writer io.Writer, value Aro) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.AroType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Username)
	ffiConverterOptionalUserProfileINSTANCE.Write(writer, value.Profile)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Name)
}

type ffiDestroyerAro struct{}

func (_ ffiDestroyerAro) Destroy(value Aro) {
	value.Destroy()
}

type Comment struct {
	ID           string
	ParentID     *string
	ForeignKey   *string
	ForeignModel *string
	Content      string
	Created      *string
	Modified     *string
	CreatedBy    *string
	ModifiedBy   *string
	Creator      *User
}

func (r *Comment) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.ParentID)
	ffiDestroyerOptionalString{}.Destroy(r.ForeignKey)
	ffiDestroyerOptionalString{}.Destroy(r.ForeignModel)
	ffiDestroyerString{}.Destroy(r.Content)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalString{}.Destroy(r.CreatedBy)
	ffiDestroyerOptionalString{}.Destroy(r.ModifiedBy)
	ffiDestroyerOptionalUser{}.Destroy(r.Creator)
}

type ffiConverterComment struct{}

var ffiConverterCommentINSTANCE = ffiConverterComment{}

func (c ffiConverterComment) Lift(rb rustBufferI) Comment {
	return liftFromRustBuffer[Comment](c, rb)
}

func (c ffiConverterComment) Read(reader io.Reader) Comment {
	return Comment{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUserINSTANCE.Read(reader),
	}
}

func (c ffiConverterComment) Lower(value Comment) C.RustBuffer {
	return lowerIntoRustBuffer[Comment](c, value)
}

func (c ffiConverterComment) LowerExternal(value Comment) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Comment](c, value))
}

func (c ffiConverterComment) Write(writer io.Writer, value Comment) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ParentID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ForeignKey)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ForeignModel)
	ffiConverterStringINSTANCE.Write(writer, value.Content)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy)
	ffiConverterOptionalUserINSTANCE.Write(writer, value.Creator)
}

type ffiDestroyerComment struct{}

func (_ ffiDestroyerComment) Destroy(value Comment) {
	value.Destroy()
}

// What blocks deleting a user or a group: each item needs a new owner, each group a new
// manager.
type DeleteBlockers struct {
	Resources []OwnedItem
	Folders   []OwnedItem
	Groups    []ManagedGroup
	// Groups the deleted user is the only member of: deleted with them.
	GroupsToDelete []string
}

func (r *DeleteBlockers) Destroy() {
	ffiDestroyerSequenceOwnedItem{}.Destroy(r.Resources)
	ffiDestroyerSequenceOwnedItem{}.Destroy(r.Folders)
	ffiDestroyerSequenceManagedGroup{}.Destroy(r.Groups)
	ffiDestroyerSequenceString{}.Destroy(r.GroupsToDelete)
}

type ffiConverterDeleteBlockers struct{}

var ffiConverterDeleteBlockersINSTANCE = ffiConverterDeleteBlockers{}

func (c ffiConverterDeleteBlockers) Lift(rb rustBufferI) DeleteBlockers {
	return liftFromRustBuffer[DeleteBlockers](c, rb)
}

func (c ffiConverterDeleteBlockers) Read(reader io.Reader) DeleteBlockers {
	return DeleteBlockers{
		ffiConverterSequenceOwnedItemINSTANCE.Read(reader),
		ffiConverterSequenceOwnedItemINSTANCE.Read(reader),
		ffiConverterSequenceManagedGroupINSTANCE.Read(reader),
		ffiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterDeleteBlockers) Lower(value DeleteBlockers) C.RustBuffer {
	return lowerIntoRustBuffer[DeleteBlockers](c, value)
}

func (c ffiConverterDeleteBlockers) LowerExternal(value DeleteBlockers) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[DeleteBlockers](c, value))
}

func (c ffiConverterDeleteBlockers) Write(writer io.Writer, value DeleteBlockers) {
	ffiConverterSequenceOwnedItemINSTANCE.Write(writer, value.Resources)
	ffiConverterSequenceOwnedItemINSTANCE.Write(writer, value.Folders)
	ffiConverterSequenceManagedGroupINSTANCE.Write(writer, value.Groups)
	ffiConverterSequenceStringINSTANCE.Write(writer, value.GroupsToDelete)
}

type ffiDestroyerDeleteBlockers struct{}

func (_ ffiDestroyerDeleteBlockers) Destroy(value DeleteBlockers) {
	value.Destroy()
}

type Favorite struct {
	ID           *string
	ForeignModel *string
	ForeignKey   *string
	Created      *string
}

func (r *Favorite) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.ForeignModel)
	ffiDestroyerOptionalString{}.Destroy(r.ForeignKey)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
}

type ffiConverterFavorite struct{}

var ffiConverterFavoriteINSTANCE = ffiConverterFavorite{}

func (c ffiConverterFavorite) Lift(rb rustBufferI) Favorite {
	return liftFromRustBuffer[Favorite](c, rb)
}

func (c ffiConverterFavorite) Read(reader io.Reader) Favorite {
	return Favorite{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterFavorite) Lower(value Favorite) C.RustBuffer {
	return lowerIntoRustBuffer[Favorite](c, value)
}

func (c ffiConverterFavorite) LowerExternal(value Favorite) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Favorite](c, value))
}

func (c ffiConverterFavorite) Write(writer io.Writer, value Favorite) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ForeignModel)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ForeignKey)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
}

type ffiDestroyerFavorite struct{}

func (_ ffiDestroyerFavorite) Destroy(value Favorite) {
	value.Destroy()
}

type Folder struct {
	ID             string
	Name           string
	FolderParentID *string
	Created        *string
	Modified       *string
	CreatedBy      *string
	ModifiedBy     *string
	Personal       *bool
	Permissions    []Permission
}

func (r *Folder) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.FolderParentID)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalString{}.Destroy(r.CreatedBy)
	ffiDestroyerOptionalString{}.Destroy(r.ModifiedBy)
	ffiDestroyerOptionalBool{}.Destroy(r.Personal)
	ffiDestroyerSequencePermission{}.Destroy(r.Permissions)
}

type ffiConverterFolder struct{}

var ffiConverterFolderINSTANCE = ffiConverterFolder{}

func (c ffiConverterFolder) Lift(rb rustBufferI) Folder {
	return liftFromRustBuffer[Folder](c, rb)
}

func (c ffiConverterFolder) Read(reader io.Reader) Folder {
	return Folder{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterSequencePermissionINSTANCE.Read(reader),
	}
}

func (c ffiConverterFolder) Lower(value Folder) C.RustBuffer {
	return lowerIntoRustBuffer[Folder](c, value)
}

func (c ffiConverterFolder) LowerExternal(value Folder) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Folder](c, value))
}

func (c ffiConverterFolder) Write(writer io.Writer, value Folder) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Personal)
	ffiConverterSequencePermissionINSTANCE.Write(writer, value.Permissions)
}

type ffiDestroyerFolder struct{}

func (_ ffiDestroyerFolder) Destroy(value Folder) {
	value.Destroy()
}

type FolderQuery struct {
	Search *string
}

func (r *FolderQuery) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.Search)
}

type ffiConverterFolderQuery struct{}

var ffiConverterFolderQueryINSTANCE = ffiConverterFolderQuery{}

func (c ffiConverterFolderQuery) Lift(rb rustBufferI) FolderQuery {
	return liftFromRustBuffer[FolderQuery](c, rb)
}

func (c ffiConverterFolderQuery) Read(reader io.Reader) FolderQuery {
	return FolderQuery{
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterFolderQuery) Lower(value FolderQuery) C.RustBuffer {
	return lowerIntoRustBuffer[FolderQuery](c, value)
}

func (c ffiConverterFolderQuery) LowerExternal(value FolderQuery) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[FolderQuery](c, value))
}

func (c ffiConverterFolderQuery) Write(writer io.Writer, value FolderQuery) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Search)
}

type ffiDestroyerFolderQuery struct{}

func (_ ffiDestroyerFolderQuery) Destroy(value FolderQuery) {
	value.Destroy()
}

type FolderTreeNode struct {
	Folder   Folder
	Children []FolderTreeNode
}

func (r *FolderTreeNode) Destroy() {
	ffiDestroyerFolder{}.Destroy(r.Folder)
	ffiDestroyerSequenceFolderTreeNode{}.Destroy(r.Children)
}

type ffiConverterFolderTreeNode struct{}

var ffiConverterFolderTreeNodeINSTANCE = ffiConverterFolderTreeNode{}

func (c ffiConverterFolderTreeNode) Lift(rb rustBufferI) FolderTreeNode {
	return liftFromRustBuffer[FolderTreeNode](c, rb)
}

func (c ffiConverterFolderTreeNode) Read(reader io.Reader) FolderTreeNode {
	return FolderTreeNode{
		ffiConverterFolderINSTANCE.Read(reader),
		ffiConverterSequenceFolderTreeNodeINSTANCE.Read(reader),
	}
}

func (c ffiConverterFolderTreeNode) Lower(value FolderTreeNode) C.RustBuffer {
	return lowerIntoRustBuffer[FolderTreeNode](c, value)
}

func (c ffiConverterFolderTreeNode) LowerExternal(value FolderTreeNode) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[FolderTreeNode](c, value))
}

func (c ffiConverterFolderTreeNode) Write(writer io.Writer, value FolderTreeNode) {
	ffiConverterFolderINSTANCE.Write(writer, value.Folder)
	ffiConverterSequenceFolderTreeNodeINSTANCE.Write(writer, value.Children)
}

type ffiDestroyerFolderTreeNode struct{}

func (_ ffiDestroyerFolderTreeNode) Destroy(value FolderTreeNode) {
	value.Destroy()
}

type GpgKey struct {
	ID          *string
	UserID      *string
	ArmoredKey  *string
	Bits        *uint32
	Fingerprint *string
	KeyCreated  *string
}

func (r *GpgKey) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.UserID)
	ffiDestroyerOptionalString{}.Destroy(r.ArmoredKey)
	ffiDestroyerOptionalUint32{}.Destroy(r.Bits)
	ffiDestroyerOptionalString{}.Destroy(r.Fingerprint)
	ffiDestroyerOptionalString{}.Destroy(r.KeyCreated)
}

type ffiConverterGpgKey struct{}

var ffiConverterGpgKeyINSTANCE = ffiConverterGpgKey{}

func (c ffiConverterGpgKey) Lift(rb rustBufferI) GpgKey {
	return liftFromRustBuffer[GpgKey](c, rb)
}

func (c ffiConverterGpgKey) Read(reader io.Reader) GpgKey {
	return GpgKey{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUint32INSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterGpgKey) Lower(value GpgKey) C.RustBuffer {
	return lowerIntoRustBuffer[GpgKey](c, value)
}

func (c ffiConverterGpgKey) LowerExternal(value GpgKey) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[GpgKey](c, value))
}

func (c ffiConverterGpgKey) Write(writer io.Writer, value GpgKey) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.UserID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ArmoredKey)
	ffiConverterOptionalUint32INSTANCE.Write(writer, value.Bits)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Fingerprint)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.KeyCreated)
}

type ffiDestroyerGpgKey struct{}

func (_ ffiDestroyerGpgKey) Destroy(value GpgKey) {
	value.Destroy()
}

type Group struct {
	ID          string
	Name        string
	Created     *string
	Modified    *string
	CreatedBy   *string
	ModifiedBy  *string
	Deleted     *bool
	GroupsUsers []GroupUser
}

func (r *Group) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalString{}.Destroy(r.CreatedBy)
	ffiDestroyerOptionalString{}.Destroy(r.ModifiedBy)
	ffiDestroyerOptionalBool{}.Destroy(r.Deleted)
	ffiDestroyerSequenceGroupUser{}.Destroy(r.GroupsUsers)
}

type ffiConverterGroup struct{}

var ffiConverterGroupINSTANCE = ffiConverterGroup{}

func (c ffiConverterGroup) Lift(rb rustBufferI) Group {
	return liftFromRustBuffer[Group](c, rb)
}

func (c ffiConverterGroup) Read(reader io.Reader) Group {
	return Group{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterSequenceGroupUserINSTANCE.Read(reader),
	}
}

func (c ffiConverterGroup) Lower(value Group) C.RustBuffer {
	return lowerIntoRustBuffer[Group](c, value)
}

func (c ffiConverterGroup) LowerExternal(value Group) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Group](c, value))
}

func (c ffiConverterGroup) Write(writer io.Writer, value Group) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Deleted)
	ffiConverterSequenceGroupUserINSTANCE.Write(writer, value.GroupsUsers)
}

type ffiDestroyerGroup struct{}

func (_ ffiDestroyerGroup) Destroy(value Group) {
	value.Destroy()
}

type GroupDeleteDryRun struct {
	ResourcesSoleGroupCount uint32
	FoldersSoleGroupCount   uint32
}

func (r *GroupDeleteDryRun) Destroy() {
	ffiDestroyerUint32{}.Destroy(r.ResourcesSoleGroupCount)
	ffiDestroyerUint32{}.Destroy(r.FoldersSoleGroupCount)
}

type ffiConverterGroupDeleteDryRun struct{}

var ffiConverterGroupDeleteDryRunINSTANCE = ffiConverterGroupDeleteDryRun{}

func (c ffiConverterGroupDeleteDryRun) Lift(rb rustBufferI) GroupDeleteDryRun {
	return liftFromRustBuffer[GroupDeleteDryRun](c, rb)
}

func (c ffiConverterGroupDeleteDryRun) Read(reader io.Reader) GroupDeleteDryRun {
	return GroupDeleteDryRun{
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
	}
}

func (c ffiConverterGroupDeleteDryRun) Lower(value GroupDeleteDryRun) C.RustBuffer {
	return lowerIntoRustBuffer[GroupDeleteDryRun](c, value)
}

func (c ffiConverterGroupDeleteDryRun) LowerExternal(value GroupDeleteDryRun) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[GroupDeleteDryRun](c, value))
}

func (c ffiConverterGroupDeleteDryRun) Write(writer io.Writer, value GroupDeleteDryRun) {
	ffiConverterUint32INSTANCE.Write(writer, value.ResourcesSoleGroupCount)
	ffiConverterUint32INSTANCE.Write(writer, value.FoldersSoleGroupCount)
}

type ffiDestroyerGroupDeleteDryRun struct{}

func (_ ffiDestroyerGroupDeleteDryRun) Destroy(value GroupDeleteDryRun) {
	value.Destroy()
}

type GroupUser struct {
	ID      *string
	GroupID *string
	UserID  *string
	IsAdmin *bool
	Created *string
}

func (r *GroupUser) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.GroupID)
	ffiDestroyerOptionalString{}.Destroy(r.UserID)
	ffiDestroyerOptionalBool{}.Destroy(r.IsAdmin)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
}

type ffiConverterGroupUser struct{}

var ffiConverterGroupUserINSTANCE = ffiConverterGroupUser{}

func (c ffiConverterGroupUser) Lift(rb rustBufferI) GroupUser {
	return liftFromRustBuffer[GroupUser](c, rb)
}

func (c ffiConverterGroupUser) Read(reader io.Reader) GroupUser {
	return GroupUser{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterGroupUser) Lower(value GroupUser) C.RustBuffer {
	return lowerIntoRustBuffer[GroupUser](c, value)
}

func (c ffiConverterGroupUser) LowerExternal(value GroupUser) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[GroupUser](c, value))
}

func (c ffiConverterGroupUser) Write(writer io.Writer, value GroupUser) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.GroupID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.UserID)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.IsAdmin)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
}

type ffiDestroyerGroupUser struct{}

func (_ ffiDestroyerGroupUser) Destroy(value GroupUser) {
	value.Destroy()
}

// How to log in, beyond the credentials.
type LoginOptions struct {
	TLSSkipVerify bool
	Proxy         *string
	// The base32 TOTP secret answering the MFA challenge without prompting.
	MfaTotpToken *string
	// The armored server public key pinned with [`fetch_server_key`]: each login then checks
	// the server holds its private key.
	ServerPublicKey *string
	// The shared metadata key fingerprint pinned with
	// [`PassboltClient::metadata_key_fingerprint`]: shared metadata is then only encrypted
	// for that key.
	MetadataKeyFingerprint *string
	// Seconds a request may take; `None` is 60, `0` waits forever.
	TimeoutSeconds *uint64
	// PEM certificate and private key, for a server asking for a client certificate (mTLS).
	ClientCertificatePem *string
	ClientKeyPem         *string
}

func (r *LoginOptions) Destroy() {
	ffiDestroyerBool{}.Destroy(r.TLSSkipVerify)
	ffiDestroyerOptionalString{}.Destroy(r.Proxy)
	ffiDestroyerOptionalString{}.Destroy(r.MfaTotpToken)
	ffiDestroyerOptionalString{}.Destroy(r.ServerPublicKey)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataKeyFingerprint)
	ffiDestroyerOptionalUint64{}.Destroy(r.TimeoutSeconds)
	ffiDestroyerOptionalString{}.Destroy(r.ClientCertificatePem)
	ffiDestroyerOptionalString{}.Destroy(r.ClientKeyPem)
}

type ffiConverterLoginOptions struct{}

var ffiConverterLoginOptionsINSTANCE = ffiConverterLoginOptions{}

func (c ffiConverterLoginOptions) Lift(rb rustBufferI) LoginOptions {
	return liftFromRustBuffer[LoginOptions](c, rb)
}

func (c ffiConverterLoginOptions) Read(reader io.Reader) LoginOptions {
	return LoginOptions{
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUint64INSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterLoginOptions) Lower(value LoginOptions) C.RustBuffer {
	return lowerIntoRustBuffer[LoginOptions](c, value)
}

func (c ffiConverterLoginOptions) LowerExternal(value LoginOptions) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[LoginOptions](c, value))
}

func (c ffiConverterLoginOptions) Write(writer io.Writer, value LoginOptions) {
	ffiConverterBoolINSTANCE.Write(writer, value.TLSSkipVerify)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Proxy)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MfaTotpToken)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ServerPublicKey)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyFingerprint)
	ffiConverterOptionalUint64INSTANCE.Write(writer, value.TimeoutSeconds)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ClientCertificatePem)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ClientKeyPem)
}

type ffiDestroyerLoginOptions struct{}

func (_ ffiDestroyerLoginOptions) Destroy(value LoginOptions) {
	value.Destroy()
}

// A group with other members that only the deleted user manages, with its memberships.
type ManagedGroup struct {
	ID          string
	Name        string
	GroupsUsers []GroupUser
}

func (r *ManagedGroup) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerSequenceGroupUser{}.Destroy(r.GroupsUsers)
}

type ffiConverterManagedGroup struct{}

var ffiConverterManagedGroupINSTANCE = ffiConverterManagedGroup{}

func (c ffiConverterManagedGroup) Lift(rb rustBufferI) ManagedGroup {
	return liftFromRustBuffer[ManagedGroup](c, rb)
}

func (c ffiConverterManagedGroup) Read(reader io.Reader) ManagedGroup {
	return ManagedGroup{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterSequenceGroupUserINSTANCE.Read(reader),
	}
}

func (c ffiConverterManagedGroup) Lower(value ManagedGroup) C.RustBuffer {
	return lowerIntoRustBuffer[ManagedGroup](c, value)
}

func (c ffiConverterManagedGroup) LowerExternal(value ManagedGroup) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ManagedGroup](c, value))
}

func (c ffiConverterManagedGroup) Write(writer io.Writer, value ManagedGroup) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterSequenceGroupUserINSTANCE.Write(writer, value.GroupsUsers)
}

type ffiDestroyerManagedGroup struct{}

func (_ ffiDestroyerManagedGroup) Destroy(value ManagedGroup) {
	value.Destroy()
}

// How metadata keys are used in the organization (admin settings).
type MetadataKeysSettings struct {
	AllowUsageOfPersonalKeys *bool
	ZeroKnowledgeKeyShare    *bool
}

func (r *MetadataKeysSettings) Destroy() {
	ffiDestroyerOptionalBool{}.Destroy(r.AllowUsageOfPersonalKeys)
	ffiDestroyerOptionalBool{}.Destroy(r.ZeroKnowledgeKeyShare)
}

type ffiConverterMetadataKeysSettings struct{}

var ffiConverterMetadataKeysSettingsINSTANCE = ffiConverterMetadataKeysSettings{}

func (c ffiConverterMetadataKeysSettings) Lift(rb rustBufferI) MetadataKeysSettings {
	return liftFromRustBuffer[MetadataKeysSettings](c, rb)
}

func (c ffiConverterMetadataKeysSettings) Read(reader io.Reader) MetadataKeysSettings {
	return MetadataKeysSettings{
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterMetadataKeysSettings) Lower(value MetadataKeysSettings) C.RustBuffer {
	return lowerIntoRustBuffer[MetadataKeysSettings](c, value)
}

func (c ffiConverterMetadataKeysSettings) LowerExternal(value MetadataKeysSettings) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[MetadataKeysSettings](c, value))
}

func (c ffiConverterMetadataKeysSettings) Write(writer io.Writer, value MetadataKeysSettings) {
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowUsageOfPersonalKeys)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.ZeroKnowledgeKeyShare)
}

type ffiDestroyerMetadataKeysSettings struct{}

func (_ ffiDestroyerMetadataKeysSettings) Destroy(value MetadataKeysSettings) {
	value.Destroy()
}

// Which metadata versions the organization creates and allows (admin settings).
type MetadataTypesSettings struct {
	DefaultResourceTypes       *string
	DefaultFolderType          *string
	DefaultTagType             *string
	DefaultCommentType         *string
	AllowCreationOfV5Resources *bool
	AllowCreationOfV5Folders   *bool
	AllowCreationOfV5Tags      *bool
	AllowCreationOfV5Comments  *bool
	AllowCreationOfV4Resources *bool
	AllowCreationOfV4Folders   *bool
	AllowCreationOfV4Tags      *bool
	AllowCreationOfV4Comments  *bool
}

func (r *MetadataTypesSettings) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.DefaultResourceTypes)
	ffiDestroyerOptionalString{}.Destroy(r.DefaultFolderType)
	ffiDestroyerOptionalString{}.Destroy(r.DefaultTagType)
	ffiDestroyerOptionalString{}.Destroy(r.DefaultCommentType)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Resources)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Folders)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Tags)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Comments)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Resources)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Folders)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Tags)
	ffiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Comments)
}

type ffiConverterMetadataTypesSettings struct{}

var ffiConverterMetadataTypesSettingsINSTANCE = ffiConverterMetadataTypesSettings{}

func (c ffiConverterMetadataTypesSettings) Lift(rb rustBufferI) MetadataTypesSettings {
	return liftFromRustBuffer[MetadataTypesSettings](c, rb)
}

func (c ffiConverterMetadataTypesSettings) Read(reader io.Reader) MetadataTypesSettings {
	return MetadataTypesSettings{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterMetadataTypesSettings) Lower(value MetadataTypesSettings) C.RustBuffer {
	return lowerIntoRustBuffer[MetadataTypesSettings](c, value)
}

func (c ffiConverterMetadataTypesSettings) LowerExternal(value MetadataTypesSettings) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[MetadataTypesSettings](c, value))
}

func (c ffiConverterMetadataTypesSettings) Write(writer io.Writer, value MetadataTypesSettings) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.DefaultResourceTypes)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.DefaultFolderType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.DefaultTagType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.DefaultCommentType)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Resources)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Folders)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Tags)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Comments)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Resources)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Folders)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Tags)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Comments)
}

type ffiDestroyerMetadataTypesSettings struct{}

func (_ ffiDestroyerMetadataTypesSettings) Destroy(value MetadataTypesSettings) {
	value.Destroy()
}

// A resource to create. Its type comes from the fields set and the server's default version,
// unless `resource_type` names it; fields the type does not have are refused.
type NewResource struct {
	Name string
	// The type slug: `password-and-description`, `v5-default`, `v5-totp-standalone`…
	ResourceType *string
	Username     *string
	// v4 types have a single URI.
	URIs        []string
	Description *string
	// The secret note of v5 types.
	Note           *string
	Password       *string
	Totp           *TotpData
	PinCode        *string
	FolderParentID *string
	// Expiry date, RFC 3339.
	Expired *string
	// A JSON object of fields set as given, last: the v5 metadata or v4 resource fields.
	MetadataFieldsJSON *string
	// A JSON object of secret fields set as given, last.
	SecretFieldsJSON *string
}

func (r *NewResource) Destroy() {
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.ResourceType)
	ffiDestroyerOptionalString{}.Destroy(r.Username)
	ffiDestroyerSequenceString{}.Destroy(r.URIs)
	ffiDestroyerOptionalString{}.Destroy(r.Description)
	ffiDestroyerOptionalString{}.Destroy(r.Note)
	ffiDestroyerOptionalString{}.Destroy(r.Password)
	ffiDestroyerOptionalTotpData{}.Destroy(r.Totp)
	ffiDestroyerOptionalString{}.Destroy(r.PinCode)
	ffiDestroyerOptionalString{}.Destroy(r.FolderParentID)
	ffiDestroyerOptionalString{}.Destroy(r.Expired)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataFieldsJSON)
	ffiDestroyerOptionalString{}.Destroy(r.SecretFieldsJSON)
}

type ffiConverterNewResource struct{}

var ffiConverterNewResourceINSTANCE = ffiConverterNewResource{}

func (c ffiConverterNewResource) Lift(rb rustBufferI) NewResource {
	return liftFromRustBuffer[NewResource](c, rb)
}

func (c ffiConverterNewResource) Read(reader io.Reader) NewResource {
	return NewResource{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterSequenceStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalTotpDataINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterNewResource) Lower(value NewResource) C.RustBuffer {
	return lowerIntoRustBuffer[NewResource](c, value)
}

func (c ffiConverterNewResource) LowerExternal(value NewResource) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[NewResource](c, value))
}

func (c ffiConverterNewResource) Write(writer io.Writer, value NewResource) {
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ResourceType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Username)
	ffiConverterSequenceStringINSTANCE.Write(writer, value.URIs)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Description)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Note)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Password)
	ffiConverterOptionalTotpDataINSTANCE.Write(writer, value.Totp)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.PinCode)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Expired)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataFieldsJSON)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.SecretFieldsJSON)
}

type ffiDestroyerNewResource struct{}

func (_ ffiDestroyerNewResource) Destroy(value NewResource) {
	value.Destroy()
}

// A shared resource or folder only the deleted user or group owns, with its permissions.
type OwnedItem struct {
	ID          string
	Permissions []Permission
}

func (r *OwnedItem) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerSequencePermission{}.Destroy(r.Permissions)
}

type ffiConverterOwnedItem struct{}

var ffiConverterOwnedItemINSTANCE = ffiConverterOwnedItem{}

func (c ffiConverterOwnedItem) Lift(rb rustBufferI) OwnedItem {
	return liftFromRustBuffer[OwnedItem](c, rb)
}

func (c ffiConverterOwnedItem) Read(reader io.Reader) OwnedItem {
	return OwnedItem{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterSequencePermissionINSTANCE.Read(reader),
	}
}

func (c ffiConverterOwnedItem) Lower(value OwnedItem) C.RustBuffer {
	return lowerIntoRustBuffer[OwnedItem](c, value)
}

func (c ffiConverterOwnedItem) LowerExternal(value OwnedItem) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[OwnedItem](c, value))
}

func (c ffiConverterOwnedItem) Write(writer io.Writer, value OwnedItem) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterSequencePermissionINSTANCE.Write(writer, value.Permissions)
}

type ffiDestroyerOwnedItem struct{}

func (_ ffiDestroyerOwnedItem) Destroy(value OwnedItem) {
	value.Destroy()
}

// How passphrases are generated; the defaults are the server's and the extension's: 9
// lowercase words of the EFF list joined by spaces.
type PassphraseGeneratorSettings struct {
	Words         uint32
	WordSeparator string
	// `None` is lowercase.
	WordCase *WordCase
	MinWords uint32
	MaxWords uint32
}

func (r *PassphraseGeneratorSettings) Destroy() {
	ffiDestroyerUint32{}.Destroy(r.Words)
	ffiDestroyerString{}.Destroy(r.WordSeparator)
	ffiDestroyerOptionalWordCase{}.Destroy(r.WordCase)
	ffiDestroyerUint32{}.Destroy(r.MinWords)
	ffiDestroyerUint32{}.Destroy(r.MaxWords)
}

type ffiConverterPassphraseGeneratorSettings struct{}

var ffiConverterPassphraseGeneratorSettingsINSTANCE = ffiConverterPassphraseGeneratorSettings{}

func (c ffiConverterPassphraseGeneratorSettings) Lift(rb rustBufferI) PassphraseGeneratorSettings {
	return liftFromRustBuffer[PassphraseGeneratorSettings](c, rb)
}

func (c ffiConverterPassphraseGeneratorSettings) Read(reader io.Reader) PassphraseGeneratorSettings {
	return PassphraseGeneratorSettings{
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalWordCaseINSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
	}
}

func (c ffiConverterPassphraseGeneratorSettings) Lower(value PassphraseGeneratorSettings) C.RustBuffer {
	return lowerIntoRustBuffer[PassphraseGeneratorSettings](c, value)
}

func (c ffiConverterPassphraseGeneratorSettings) LowerExternal(value PassphraseGeneratorSettings) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[PassphraseGeneratorSettings](c, value))
}

func (c ffiConverterPassphraseGeneratorSettings) Write(writer io.Writer, value PassphraseGeneratorSettings) {
	ffiConverterUint32INSTANCE.Write(writer, value.Words)
	ffiConverterStringINSTANCE.Write(writer, value.WordSeparator)
	ffiConverterOptionalWordCaseINSTANCE.Write(writer, value.WordCase)
	ffiConverterUint32INSTANCE.Write(writer, value.MinWords)
	ffiConverterUint32INSTANCE.Write(writer, value.MaxWords)
}

type ffiDestroyerPassphraseGeneratorSettings struct{}

func (_ ffiDestroyerPassphraseGeneratorSettings) Destroy(value PassphraseGeneratorSettings) {
	value.Destroy()
}

type PasswordExpirySettings struct {
	ID                      *string
	DefaultExpiryPeriodDays *uint32
	PolicyOverride          *bool
	AutomaticExpiry         *bool
	AutomaticUpdate         *bool
}

func (r *PasswordExpirySettings) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalUint32{}.Destroy(r.DefaultExpiryPeriodDays)
	ffiDestroyerOptionalBool{}.Destroy(r.PolicyOverride)
	ffiDestroyerOptionalBool{}.Destroy(r.AutomaticExpiry)
	ffiDestroyerOptionalBool{}.Destroy(r.AutomaticUpdate)
}

type ffiConverterPasswordExpirySettings struct{}

var ffiConverterPasswordExpirySettingsINSTANCE = ffiConverterPasswordExpirySettings{}

func (c ffiConverterPasswordExpirySettings) Lift(rb rustBufferI) PasswordExpirySettings {
	return liftFromRustBuffer[PasswordExpirySettings](c, rb)
}

func (c ffiConverterPasswordExpirySettings) Read(reader io.Reader) PasswordExpirySettings {
	return PasswordExpirySettings{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUint32INSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterPasswordExpirySettings) Lower(value PasswordExpirySettings) C.RustBuffer {
	return lowerIntoRustBuffer[PasswordExpirySettings](c, value)
}

func (c ffiConverterPasswordExpirySettings) LowerExternal(value PasswordExpirySettings) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[PasswordExpirySettings](c, value))
}

func (c ffiConverterPasswordExpirySettings) Write(writer io.Writer, value PasswordExpirySettings) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalUint32INSTANCE.Write(writer, value.DefaultExpiryPeriodDays)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.PolicyOverride)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AutomaticExpiry)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.AutomaticUpdate)
}

type ffiDestroyerPasswordExpirySettings struct{}

func (_ ffiDestroyerPasswordExpirySettings) Destroy(value PasswordExpirySettings) {
	value.Destroy()
}

// How passwords are generated; the defaults are the server's and the extension's: 18
// characters of every set but emoji, without look-alike characters.
type PasswordGeneratorSettings struct {
	Length    uint32
	MinLength uint32
	MaxLength uint32
	// `A-Z`
	MaskUpper bool
	// `a-z`
	MaskLower bool
	// `0-9`
	MaskDigit bool
	// `{ [ ( | ) ] }`
	MaskParenthesis bool
	// The emoticons of Unicode 6.
	MaskEmoji bool
	// `# $ % & @ ^ ~`
	MaskChar1 bool
	// `. , : ;`
	MaskChar2 bool
	// `'`, `"` and the backtick
	MaskChar3 bool
	// `/ \ _ -`
	MaskChar4 bool
	// `< * + ! ? =`
	MaskChar5 bool
	// Leaves out `O l | I 0 1`.
	ExcludeLookAlikeChars bool
}

func (r *PasswordGeneratorSettings) Destroy() {
	ffiDestroyerUint32{}.Destroy(r.Length)
	ffiDestroyerUint32{}.Destroy(r.MinLength)
	ffiDestroyerUint32{}.Destroy(r.MaxLength)
	ffiDestroyerBool{}.Destroy(r.MaskUpper)
	ffiDestroyerBool{}.Destroy(r.MaskLower)
	ffiDestroyerBool{}.Destroy(r.MaskDigit)
	ffiDestroyerBool{}.Destroy(r.MaskParenthesis)
	ffiDestroyerBool{}.Destroy(r.MaskEmoji)
	ffiDestroyerBool{}.Destroy(r.MaskChar1)
	ffiDestroyerBool{}.Destroy(r.MaskChar2)
	ffiDestroyerBool{}.Destroy(r.MaskChar3)
	ffiDestroyerBool{}.Destroy(r.MaskChar4)
	ffiDestroyerBool{}.Destroy(r.MaskChar5)
	ffiDestroyerBool{}.Destroy(r.ExcludeLookAlikeChars)
}

type ffiConverterPasswordGeneratorSettings struct{}

var ffiConverterPasswordGeneratorSettingsINSTANCE = ffiConverterPasswordGeneratorSettings{}

func (c ffiConverterPasswordGeneratorSettings) Lift(rb rustBufferI) PasswordGeneratorSettings {
	return liftFromRustBuffer[PasswordGeneratorSettings](c, rb)
}

func (c ffiConverterPasswordGeneratorSettings) Read(reader io.Reader) PasswordGeneratorSettings {
	return PasswordGeneratorSettings{
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterPasswordGeneratorSettings) Lower(value PasswordGeneratorSettings) C.RustBuffer {
	return lowerIntoRustBuffer[PasswordGeneratorSettings](c, value)
}

func (c ffiConverterPasswordGeneratorSettings) LowerExternal(value PasswordGeneratorSettings) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[PasswordGeneratorSettings](c, value))
}

func (c ffiConverterPasswordGeneratorSettings) Write(writer io.Writer, value PasswordGeneratorSettings) {
	ffiConverterUint32INSTANCE.Write(writer, value.Length)
	ffiConverterUint32INSTANCE.Write(writer, value.MinLength)
	ffiConverterUint32INSTANCE.Write(writer, value.MaxLength)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskUpper)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskLower)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskDigit)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskParenthesis)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskEmoji)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskChar1)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskChar2)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskChar3)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskChar4)
	ffiConverterBoolINSTANCE.Write(writer, value.MaskChar5)
	ffiConverterBoolINSTANCE.Write(writer, value.ExcludeLookAlikeChars)
}

type ffiDestroyerPasswordGeneratorSettings struct{}

func (_ ffiDestroyerPasswordGeneratorSettings) Destroy(value PasswordGeneratorSettings) {
	value.Destroy()
}

// The password policies of the organization: the generator to use and its settings.
type PasswordPolicies struct {
	DefaultGenerator            GeneratorType
	PasswordGeneratorSettings   PasswordGeneratorSettings
	PassphraseGeneratorSettings PassphraseGeneratorSettings
	// Check new passwords against Have I Been Pwned.
	ExternalDictionaryCheck bool
	// Where the server read them: `default`, `file`, `env`, `db`…
	Source *string
	// Set once an administrator saved them (Passbolt Pro).
	ID *string
}

func (r *PasswordPolicies) Destroy() {
	ffiDestroyerGeneratorType{}.Destroy(r.DefaultGenerator)
	ffiDestroyerPasswordGeneratorSettings{}.Destroy(r.PasswordGeneratorSettings)
	ffiDestroyerPassphraseGeneratorSettings{}.Destroy(r.PassphraseGeneratorSettings)
	ffiDestroyerBool{}.Destroy(r.ExternalDictionaryCheck)
	ffiDestroyerOptionalString{}.Destroy(r.Source)
	ffiDestroyerOptionalString{}.Destroy(r.ID)
}

type ffiConverterPasswordPolicies struct{}

var ffiConverterPasswordPoliciesINSTANCE = ffiConverterPasswordPolicies{}

func (c ffiConverterPasswordPolicies) Lift(rb rustBufferI) PasswordPolicies {
	return liftFromRustBuffer[PasswordPolicies](c, rb)
}

func (c ffiConverterPasswordPolicies) Read(reader io.Reader) PasswordPolicies {
	return PasswordPolicies{
		ffiConverterGeneratorTypeINSTANCE.Read(reader),
		ffiConverterPasswordGeneratorSettingsINSTANCE.Read(reader),
		ffiConverterPassphraseGeneratorSettingsINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterPasswordPolicies) Lower(value PasswordPolicies) C.RustBuffer {
	return lowerIntoRustBuffer[PasswordPolicies](c, value)
}

func (c ffiConverterPasswordPolicies) LowerExternal(value PasswordPolicies) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[PasswordPolicies](c, value))
}

func (c ffiConverterPasswordPolicies) Write(writer io.Writer, value PasswordPolicies) {
	ffiConverterGeneratorTypeINSTANCE.Write(writer, value.DefaultGenerator)
	ffiConverterPasswordGeneratorSettingsINSTANCE.Write(writer, value.PasswordGeneratorSettings)
	ffiConverterPassphraseGeneratorSettingsINSTANCE.Write(writer, value.PassphraseGeneratorSettings)
	ffiConverterBoolINSTANCE.Write(writer, value.ExternalDictionaryCheck)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Source)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
}

type ffiDestroyerPasswordPolicies struct{}

func (_ ffiDestroyerPasswordPolicies) Destroy(value PasswordPolicies) {
	value.Destroy()
}

type Permission struct {
	ID             *string
	Aco            *string
	AcoForeignKey  *string
	Aro            *string
	AroForeignKey  *string
	PermissionType *int32
	Created        *string
	Modified       *string
	User           *User
	Group          *Group
}

func (r *Permission) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.Aco)
	ffiDestroyerOptionalString{}.Destroy(r.AcoForeignKey)
	ffiDestroyerOptionalString{}.Destroy(r.Aro)
	ffiDestroyerOptionalString{}.Destroy(r.AroForeignKey)
	ffiDestroyerOptionalInt32{}.Destroy(r.PermissionType)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalUser{}.Destroy(r.User)
	ffiDestroyerOptionalGroup{}.Destroy(r.Group)
}

type ffiConverterPermission struct{}

var ffiConverterPermissionINSTANCE = ffiConverterPermission{}

func (c ffiConverterPermission) Lift(rb rustBufferI) Permission {
	return liftFromRustBuffer[Permission](c, rb)
}

func (c ffiConverterPermission) Read(reader io.Reader) Permission {
	return Permission{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalInt32INSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUserINSTANCE.Read(reader),
		ffiConverterOptionalGroupINSTANCE.Read(reader),
	}
}

func (c ffiConverterPermission) Lower(value Permission) C.RustBuffer {
	return lowerIntoRustBuffer[Permission](c, value)
}

func (c ffiConverterPermission) LowerExternal(value Permission) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Permission](c, value))
}

func (c ffiConverterPermission) Write(writer io.Writer, value Permission) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Aco)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.AcoForeignKey)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Aro)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.AroForeignKey)
	ffiConverterOptionalInt32INSTANCE.Write(writer, value.PermissionType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalUserINSTANCE.Write(writer, value.User)
	ffiConverterOptionalGroupINSTANCE.Write(writer, value.Group)
}

type ffiDestroyerPermission struct{}

func (_ ffiDestroyerPermission) Destroy(value Permission) {
	value.Destroy()
}

type Resource struct {
	ID             string
	Name           string
	Username       *string
	URI            *string
	Description    *string
	FolderParentID *string
	ResourceTypeID *string
	Created        *string
	Modified       *string
	CreatedBy      *string
	ModifiedBy     *string
	Personal       *bool
	Favorite       *Favorite
	Secrets        []Secret
	Permissions    []Permission
	Expired        *string
	// v5 only: PGP-armored encrypted metadata.
	Metadata        *string
	MetadataKeyID   *string
	MetadataKeyType *string
}

func (r *Resource) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.Username)
	ffiDestroyerOptionalString{}.Destroy(r.URI)
	ffiDestroyerOptionalString{}.Destroy(r.Description)
	ffiDestroyerOptionalString{}.Destroy(r.FolderParentID)
	ffiDestroyerOptionalString{}.Destroy(r.ResourceTypeID)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalString{}.Destroy(r.CreatedBy)
	ffiDestroyerOptionalString{}.Destroy(r.ModifiedBy)
	ffiDestroyerOptionalBool{}.Destroy(r.Personal)
	ffiDestroyerOptionalFavorite{}.Destroy(r.Favorite)
	ffiDestroyerSequenceSecret{}.Destroy(r.Secrets)
	ffiDestroyerSequencePermission{}.Destroy(r.Permissions)
	ffiDestroyerOptionalString{}.Destroy(r.Expired)
	ffiDestroyerOptionalString{}.Destroy(r.Metadata)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataKeyID)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataKeyType)
}

type ffiConverterResource struct{}

var ffiConverterResourceINSTANCE = ffiConverterResource{}

func (c ffiConverterResource) Lift(rb rustBufferI) Resource {
	return liftFromRustBuffer[Resource](c, rb)
}

func (c ffiConverterResource) Read(reader io.Reader) Resource {
	return Resource{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalFavoriteINSTANCE.Read(reader),
		ffiConverterSequenceSecretINSTANCE.Read(reader),
		ffiConverterSequencePermissionINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterResource) Lower(value Resource) C.RustBuffer {
	return lowerIntoRustBuffer[Resource](c, value)
}

func (c ffiConverterResource) LowerExternal(value Resource) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Resource](c, value))
}

func (c ffiConverterResource) Write(writer io.Writer, value Resource) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Username)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.URI)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Description)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ResourceTypeID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Personal)
	ffiConverterOptionalFavoriteINSTANCE.Write(writer, value.Favorite)
	ffiConverterSequenceSecretINSTANCE.Write(writer, value.Secrets)
	ffiConverterSequencePermissionINSTANCE.Write(writer, value.Permissions)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Expired)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Metadata)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyType)
}

type ffiDestroyerResource struct{}

func (_ ffiDestroyerResource) Destroy(value Resource) {
	value.Destroy()
}

// Changes to a resource; `None` keeps the current value.
type ResourceChanges struct {
	Name     *string
	Username *string
	// v4 types have a single URI.
	URIs        *[]string
	Description *string
	// The secret note of v5 types.
	Note     *string
	Password *string
	PinCode  *string
	// The TOTP fields to change. Adding a TOTP switches to the type with a TOTP.
	Totp *TotpData
	// Switches to the type without TOTP.
	RemoveTotp bool
	// The new expiry date, RFC 3339.
	Expired *string
	// Clears the expiry.
	ClearExpiry bool
	// A JSON object of fields set as given, last: the v5 metadata or v4 resource fields.
	MetadataFieldsJSON *string
	// A JSON object of secret fields set as given, last.
	SecretFieldsJSON *string
}

func (r *ResourceChanges) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.Username)
	ffiDestroyerOptionalSequenceString{}.Destroy(r.URIs)
	ffiDestroyerOptionalString{}.Destroy(r.Description)
	ffiDestroyerOptionalString{}.Destroy(r.Note)
	ffiDestroyerOptionalString{}.Destroy(r.Password)
	ffiDestroyerOptionalString{}.Destroy(r.PinCode)
	ffiDestroyerOptionalTotpData{}.Destroy(r.Totp)
	ffiDestroyerBool{}.Destroy(r.RemoveTotp)
	ffiDestroyerOptionalString{}.Destroy(r.Expired)
	ffiDestroyerBool{}.Destroy(r.ClearExpiry)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataFieldsJSON)
	ffiDestroyerOptionalString{}.Destroy(r.SecretFieldsJSON)
}

type ffiConverterResourceChanges struct{}

var ffiConverterResourceChangesINSTANCE = ffiConverterResourceChanges{}

func (c ffiConverterResourceChanges) Lift(rb rustBufferI) ResourceChanges {
	return liftFromRustBuffer[ResourceChanges](c, rb)
}

func (c ffiConverterResourceChanges) Read(reader io.Reader) ResourceChanges {
	return ResourceChanges{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalSequenceStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalTotpDataINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterResourceChanges) Lower(value ResourceChanges) C.RustBuffer {
	return lowerIntoRustBuffer[ResourceChanges](c, value)
}

func (c ffiConverterResourceChanges) LowerExternal(value ResourceChanges) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ResourceChanges](c, value))
}

func (c ffiConverterResourceChanges) Write(writer io.Writer, value ResourceChanges) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Username)
	ffiConverterOptionalSequenceStringINSTANCE.Write(writer, value.URIs)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Description)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Note)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Password)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.PinCode)
	ffiConverterOptionalTotpDataINSTANCE.Write(writer, value.Totp)
	ffiConverterBoolINSTANCE.Write(writer, value.RemoveTotp)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Expired)
	ffiConverterBoolINSTANCE.Write(writer, value.ClearExpiry)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataFieldsJSON)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.SecretFieldsJSON)
}

type ffiDestroyerResourceChanges struct{}

func (_ ffiDestroyerResourceChanges) Destroy(value ResourceChanges) {
	value.Destroy()
}

type ResourceQuery struct {
	Search        *string
	FavoritesOnly bool
	OwnedByMe     bool
}

func (r *ResourceQuery) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.Search)
	ffiDestroyerBool{}.Destroy(r.FavoritesOnly)
	ffiDestroyerBool{}.Destroy(r.OwnedByMe)
}

type ffiConverterResourceQuery struct{}

var ffiConverterResourceQueryINSTANCE = ffiConverterResourceQuery{}

func (c ffiConverterResourceQuery) Lift(rb rustBufferI) ResourceQuery {
	return liftFromRustBuffer[ResourceQuery](c, rb)
}

func (c ffiConverterResourceQuery) Read(reader io.Reader) ResourceQuery {
	return ResourceQuery{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterResourceQuery) Lower(value ResourceQuery) C.RustBuffer {
	return lowerIntoRustBuffer[ResourceQuery](c, value)
}

func (c ffiConverterResourceQuery) LowerExternal(value ResourceQuery) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ResourceQuery](c, value))
}

func (c ffiConverterResourceQuery) Write(writer io.Writer, value ResourceQuery) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Search)
	ffiConverterBoolINSTANCE.Write(writer, value.FavoritesOnly)
	ffiConverterBoolINSTANCE.Write(writer, value.OwnedByMe)
}

type ffiDestroyerResourceQuery struct{}

func (_ ffiDestroyerResourceQuery) Destroy(value ResourceQuery) {
	value.Destroy()
}

// A resource type of the server; `definition` is its JSON Schema, as JSON.
type ResourceType struct {
	ID         string
	Slug       string
	Name       *string
	Definition *string
}

func (r *ResourceType) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Slug)
	ffiDestroyerOptionalString{}.Destroy(r.Name)
	ffiDestroyerOptionalString{}.Destroy(r.Definition)
}

type ffiConverterResourceType struct{}

var ffiConverterResourceTypeINSTANCE = ffiConverterResourceType{}

func (c ffiConverterResourceType) Lift(rb rustBufferI) ResourceType {
	return liftFromRustBuffer[ResourceType](c, rb)
}

func (c ffiConverterResourceType) Read(reader io.Reader) ResourceType {
	return ResourceType{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterResourceType) Lower(value ResourceType) C.RustBuffer {
	return lowerIntoRustBuffer[ResourceType](c, value)
}

func (c ffiConverterResourceType) LowerExternal(value ResourceType) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ResourceType](c, value))
}

func (c ffiConverterResourceType) Write(writer io.Writer, value ResourceType) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Slug)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Name)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Definition)
}

type ffiDestroyerResourceType struct{}

func (_ ffiDestroyerResourceType) Destroy(value ResourceType) {
	value.Destroy()
}

// A resource with its v5 metadata decrypted, and its secret when it was asked for.
type ResourceView struct {
	ID       string
	Name     string
	Username string
	// The first of `uris`.
	URI  string
	URIs []string
	// The v5 metadata description, else the v4 one.
	Description    string
	FolderParentID *string
	// The type slug; `None` for a type the server does not list.
	ResourceType   *string
	ResourceTypeID *string
	Personal       *bool
	// `user_key` (personal) or `shared_key` for v5 resources.
	MetadataKeyType *string
	Created         *string
	Modified        *string
	Expired         *string
	Password        *string
	Totp            *TotpData
	// The decrypted v5 metadata, or the v4 fields, as a JSON object: the icon and custom
	// fields among them.
	MetadataJSON string
	// The decrypted secret as a JSON object, when it was asked for and decrypted.
	SecretJSON *string
	// Why the metadata or the secret could not be decrypted.
	Error *string
}

func (r *ResourceView) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Name)
	ffiDestroyerString{}.Destroy(r.Username)
	ffiDestroyerString{}.Destroy(r.URI)
	ffiDestroyerSequenceString{}.Destroy(r.URIs)
	ffiDestroyerString{}.Destroy(r.Description)
	ffiDestroyerOptionalString{}.Destroy(r.FolderParentID)
	ffiDestroyerOptionalString{}.Destroy(r.ResourceType)
	ffiDestroyerOptionalString{}.Destroy(r.ResourceTypeID)
	ffiDestroyerOptionalBool{}.Destroy(r.Personal)
	ffiDestroyerOptionalString{}.Destroy(r.MetadataKeyType)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalString{}.Destroy(r.Expired)
	ffiDestroyerOptionalString{}.Destroy(r.Password)
	ffiDestroyerOptionalTotpData{}.Destroy(r.Totp)
	ffiDestroyerString{}.Destroy(r.MetadataJSON)
	ffiDestroyerOptionalString{}.Destroy(r.SecretJSON)
	ffiDestroyerOptionalString{}.Destroy(r.Error)
}

type ffiConverterResourceView struct{}

var ffiConverterResourceViewINSTANCE = ffiConverterResourceView{}

func (c ffiConverterResourceView) Lift(rb rustBufferI) ResourceView {
	return liftFromRustBuffer[ResourceView](c, rb)
}

func (c ffiConverterResourceView) Read(reader io.Reader) ResourceView {
	return ResourceView{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterSequenceStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalTotpDataINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterResourceView) Lower(value ResourceView) C.RustBuffer {
	return lowerIntoRustBuffer[ResourceView](c, value)
}

func (c ffiConverterResourceView) LowerExternal(value ResourceView) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ResourceView](c, value))
}

func (c ffiConverterResourceView) Write(writer io.Writer, value ResourceView) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Name)
	ffiConverterStringINSTANCE.Write(writer, value.Username)
	ffiConverterStringINSTANCE.Write(writer, value.URI)
	ffiConverterSequenceStringINSTANCE.Write(writer, value.URIs)
	ffiConverterStringINSTANCE.Write(writer, value.Description)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ResourceType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ResourceTypeID)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Personal)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyType)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Expired)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Password)
	ffiConverterOptionalTotpDataINSTANCE.Write(writer, value.Totp)
	ffiConverterStringINSTANCE.Write(writer, value.MetadataJSON)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.SecretJSON)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Error)
}

type ffiDestroyerResourceView struct{}

func (_ ffiDestroyerResourceView) Destroy(value ResourceView) {
	value.Destroy()
}

type Role struct {
	ID   *string
	Name *string
}

func (r *Role) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.Name)
}

type ffiConverterRole struct{}

var ffiConverterRoleINSTANCE = ffiConverterRole{}

func (c ffiConverterRole) Lift(rb rustBufferI) Role {
	return liftFromRustBuffer[Role](c, rb)
}

func (c ffiConverterRole) Read(reader io.Reader) Role {
	return Role{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterRole) Lower(value Role) C.RustBuffer {
	return lowerIntoRustBuffer[Role](c, value)
}

func (c ffiConverterRole) LowerExternal(value Role) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Role](c, value))
}

func (c ffiConverterRole) Write(writer io.Writer, value Role) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Name)
}

type ffiDestroyerRole struct{}

func (_ ffiDestroyerRole) Destroy(value Role) {
	value.Destroy()
}

type Secret struct {
	ID         *string
	ResourceID *string
	UserID     *string
	Data       *string
	Created    *string
	Modified   *string
}

func (r *Secret) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.ResourceID)
	ffiDestroyerOptionalString{}.Destroy(r.UserID)
	ffiDestroyerOptionalString{}.Destroy(r.Data)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
}

type ffiConverterSecret struct{}

var ffiConverterSecretINSTANCE = ffiConverterSecret{}

func (c ffiConverterSecret) Lift(rb rustBufferI) Secret {
	return liftFromRustBuffer[Secret](c, rb)
}

func (c ffiConverterSecret) Read(reader io.Reader) Secret {
	return Secret{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterSecret) Lower(value Secret) C.RustBuffer {
	return lowerIntoRustBuffer[Secret](c, value)
}

func (c ffiConverterSecret) LowerExternal(value Secret) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Secret](c, value))
}

func (c ffiConverterSecret) Write(writer io.Writer, value Secret) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.ResourceID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.UserID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Data)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
}

type ffiDestroyerSecret struct{}

func (_ ffiDestroyerSecret) Destroy(value Secret) {
	value.Destroy()
}

type SecretData struct {
	Password    *string
	Description *string
	Totp        *TotpData
	Raw         *string
}

func (r *SecretData) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.Password)
	ffiDestroyerOptionalString{}.Destroy(r.Description)
	ffiDestroyerOptionalTotpData{}.Destroy(r.Totp)
	ffiDestroyerOptionalString{}.Destroy(r.Raw)
}

type ffiConverterSecretData struct{}

var ffiConverterSecretDataINSTANCE = ffiConverterSecretData{}

func (c ffiConverterSecretData) Lift(rb rustBufferI) SecretData {
	return liftFromRustBuffer[SecretData](c, rb)
}

func (c ffiConverterSecretData) Read(reader io.Reader) SecretData {
	return SecretData{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalTotpDataINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterSecretData) Lower(value SecretData) C.RustBuffer {
	return lowerIntoRustBuffer[SecretData](c, value)
}

func (c ffiConverterSecretData) LowerExternal(value SecretData) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[SecretData](c, value))
}

func (c ffiConverterSecretData) Write(writer io.Writer, value SecretData) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Password)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Description)
	ffiConverterOptionalTotpDataINSTANCE.Write(writer, value.Totp)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Raw)
}

type ffiDestroyerSecretData struct{}

func (_ ffiDestroyerSecretData) Destroy(value SecretData) {
	value.Destroy()
}

// The server public key, to pin.
type ServerKey struct {
	// Computed from the key, checked against the one the server announces.
	Fingerprint string
	ArmoredKey  string
}

func (r *ServerKey) Destroy() {
	ffiDestroyerString{}.Destroy(r.Fingerprint)
	ffiDestroyerString{}.Destroy(r.ArmoredKey)
}

type ffiConverterServerKey struct{}

var ffiConverterServerKeyINSTANCE = ffiConverterServerKey{}

func (c ffiConverterServerKey) Lift(rb rustBufferI) ServerKey {
	return liftFromRustBuffer[ServerKey](c, rb)
}

func (c ffiConverterServerKey) Read(reader io.Reader) ServerKey {
	return ServerKey{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterServerKey) Lower(value ServerKey) C.RustBuffer {
	return lowerIntoRustBuffer[ServerKey](c, value)
}

func (c ffiConverterServerKey) LowerExternal(value ServerKey) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[ServerKey](c, value))
}

func (c ffiConverterServerKey) Write(writer io.Writer, value ServerKey) {
	ffiConverterStringINSTANCE.Write(writer, value.Fingerprint)
	ffiConverterStringINSTANCE.Write(writer, value.ArmoredKey)
}

type ffiDestroyerServerKey struct{}

func (_ ffiDestroyerServerKey) Destroy(value ServerKey) {
	value.Destroy()
}

type Tag struct {
	ID       string
	Slug     string
	IsShared *bool
	Created  *string
	Modified *string
}

func (r *Tag) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerString{}.Destroy(r.Slug)
	ffiDestroyerOptionalBool{}.Destroy(r.IsShared)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
}

type ffiConverterTag struct{}

var ffiConverterTagINSTANCE = ffiConverterTag{}

func (c ffiConverterTag) Lift(rb rustBufferI) Tag {
	return liftFromRustBuffer[Tag](c, rb)
}

func (c ffiConverterTag) Read(reader io.Reader) Tag {
	return Tag{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterTag) Lower(value Tag) C.RustBuffer {
	return lowerIntoRustBuffer[Tag](c, value)
}

func (c ffiConverterTag) LowerExternal(value Tag) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Tag](c, value))
}

func (c ffiConverterTag) Write(writer io.Writer, value Tag) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterStringINSTANCE.Write(writer, value.Slug)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.IsShared)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
}

type ffiDestroyerTag struct{}

func (_ ffiDestroyerTag) Destroy(value Tag) {
	value.Destroy()
}

type TotpData struct {
	SecretKey *string
	Algorithm *string
	Digits    *uint32
	Period    *uint64
	Issuer    *string
}

func (r *TotpData) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.SecretKey)
	ffiDestroyerOptionalString{}.Destroy(r.Algorithm)
	ffiDestroyerOptionalUint32{}.Destroy(r.Digits)
	ffiDestroyerOptionalUint64{}.Destroy(r.Period)
	ffiDestroyerOptionalString{}.Destroy(r.Issuer)
}

type ffiConverterTotpData struct{}

var ffiConverterTotpDataINSTANCE = ffiConverterTotpData{}

func (c ffiConverterTotpData) Lift(rb rustBufferI) TotpData {
	return liftFromRustBuffer[TotpData](c, rb)
}

func (c ffiConverterTotpData) Read(reader io.Reader) TotpData {
	return TotpData{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalUint32INSTANCE.Read(reader),
		ffiConverterOptionalUint64INSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterTotpData) Lower(value TotpData) C.RustBuffer {
	return lowerIntoRustBuffer[TotpData](c, value)
}

func (c ffiConverterTotpData) LowerExternal(value TotpData) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[TotpData](c, value))
}

func (c ffiConverterTotpData) Write(writer io.Writer, value TotpData) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.SecretKey)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Algorithm)
	ffiConverterOptionalUint32INSTANCE.Write(writer, value.Digits)
	ffiConverterOptionalUint64INSTANCE.Write(writer, value.Period)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Issuer)
}

type ffiDestroyerTotpData struct{}

func (_ ffiDestroyerTotpData) Destroy(value TotpData) {
	value.Destroy()
}

type User struct {
	ID       string
	Username *string
	RoleID   *string
	Created  *string
	Modified *string
	Active   *bool
	Deleted  *bool
	Profile  *UserProfile
	Role     *Role
	GpgKey   *GpgKey
}

func (r *User) Destroy() {
	ffiDestroyerString{}.Destroy(r.ID)
	ffiDestroyerOptionalString{}.Destroy(r.Username)
	ffiDestroyerOptionalString{}.Destroy(r.RoleID)
	ffiDestroyerOptionalString{}.Destroy(r.Created)
	ffiDestroyerOptionalString{}.Destroy(r.Modified)
	ffiDestroyerOptionalBool{}.Destroy(r.Active)
	ffiDestroyerOptionalBool{}.Destroy(r.Deleted)
	ffiDestroyerOptionalUserProfile{}.Destroy(r.Profile)
	ffiDestroyerOptionalRole{}.Destroy(r.Role)
	ffiDestroyerOptionalGpgKey{}.Destroy(r.GpgKey)
}

type ffiConverterUser struct{}

var ffiConverterUserINSTANCE = ffiConverterUser{}

func (c ffiConverterUser) Lift(rb rustBufferI) User {
	return liftFromRustBuffer[User](c, rb)
}

func (c ffiConverterUser) Read(reader io.Reader) User {
	return User{
		ffiConverterStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalBoolINSTANCE.Read(reader),
		ffiConverterOptionalUserProfileINSTANCE.Read(reader),
		ffiConverterOptionalRoleINSTANCE.Read(reader),
		ffiConverterOptionalGpgKeyINSTANCE.Read(reader),
	}
}

func (c ffiConverterUser) Lower(value User) C.RustBuffer {
	return lowerIntoRustBuffer[User](c, value)
}

func (c ffiConverterUser) LowerExternal(value User) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[User](c, value))
}

func (c ffiConverterUser) Write(writer io.Writer, value User) {
	ffiConverterStringINSTANCE.Write(writer, value.ID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Username)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.RoleID)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Created)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Modified)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Active)
	ffiConverterOptionalBoolINSTANCE.Write(writer, value.Deleted)
	ffiConverterOptionalUserProfileINSTANCE.Write(writer, value.Profile)
	ffiConverterOptionalRoleINSTANCE.Write(writer, value.Role)
	ffiConverterOptionalGpgKeyINSTANCE.Write(writer, value.GpgKey)
}

type ffiDestroyerUser struct{}

func (_ ffiDestroyerUser) Destroy(value User) {
	value.Destroy()
}

type UserDeleteDryRun struct {
	ResourcesSoleOwnerCount uint32
	FoldersSoleOwnerCount   uint32
	GroupsSoleManagerCount  uint32
}

func (r *UserDeleteDryRun) Destroy() {
	ffiDestroyerUint32{}.Destroy(r.ResourcesSoleOwnerCount)
	ffiDestroyerUint32{}.Destroy(r.FoldersSoleOwnerCount)
	ffiDestroyerUint32{}.Destroy(r.GroupsSoleManagerCount)
}

type ffiConverterUserDeleteDryRun struct{}

var ffiConverterUserDeleteDryRunINSTANCE = ffiConverterUserDeleteDryRun{}

func (c ffiConverterUserDeleteDryRun) Lift(rb rustBufferI) UserDeleteDryRun {
	return liftFromRustBuffer[UserDeleteDryRun](c, rb)
}

func (c ffiConverterUserDeleteDryRun) Read(reader io.Reader) UserDeleteDryRun {
	return UserDeleteDryRun{
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
		ffiConverterUint32INSTANCE.Read(reader),
	}
}

func (c ffiConverterUserDeleteDryRun) Lower(value UserDeleteDryRun) C.RustBuffer {
	return lowerIntoRustBuffer[UserDeleteDryRun](c, value)
}

func (c ffiConverterUserDeleteDryRun) LowerExternal(value UserDeleteDryRun) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[UserDeleteDryRun](c, value))
}

func (c ffiConverterUserDeleteDryRun) Write(writer io.Writer, value UserDeleteDryRun) {
	ffiConverterUint32INSTANCE.Write(writer, value.ResourcesSoleOwnerCount)
	ffiConverterUint32INSTANCE.Write(writer, value.FoldersSoleOwnerCount)
	ffiConverterUint32INSTANCE.Write(writer, value.GroupsSoleManagerCount)
}

type ffiDestroyerUserDeleteDryRun struct{}

func (_ ffiDestroyerUserDeleteDryRun) Destroy(value UserDeleteDryRun) {
	value.Destroy()
}

type UserProfile struct {
	FirstName *string
	LastName  *string
}

func (r *UserProfile) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.FirstName)
	ffiDestroyerOptionalString{}.Destroy(r.LastName)
}

type ffiConverterUserProfile struct{}

var ffiConverterUserProfileINSTANCE = ffiConverterUserProfile{}

func (c ffiConverterUserProfile) Lift(rb rustBufferI) UserProfile {
	return liftFromRustBuffer[UserProfile](c, rb)
}

func (c ffiConverterUserProfile) Read(reader io.Reader) UserProfile {
	return UserProfile{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c ffiConverterUserProfile) Lower(value UserProfile) C.RustBuffer {
	return lowerIntoRustBuffer[UserProfile](c, value)
}

func (c ffiConverterUserProfile) LowerExternal(value UserProfile) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[UserProfile](c, value))
}

func (c ffiConverterUserProfile) Write(writer io.Writer, value UserProfile) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.FirstName)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.LastName)
}

type ffiDestroyerUserProfile struct{}

func (_ ffiDestroyerUserProfile) Destroy(value UserProfile) {
	value.Destroy()
}

type UserQuery struct {
	Search    *string
	GroupID   *string
	AdminOnly bool
}

func (r *UserQuery) Destroy() {
	ffiDestroyerOptionalString{}.Destroy(r.Search)
	ffiDestroyerOptionalString{}.Destroy(r.GroupID)
	ffiDestroyerBool{}.Destroy(r.AdminOnly)
}

type ffiConverterUserQuery struct{}

var ffiConverterUserQueryINSTANCE = ffiConverterUserQuery{}

func (c ffiConverterUserQuery) Lift(rb rustBufferI) UserQuery {
	return liftFromRustBuffer[UserQuery](c, rb)
}

func (c ffiConverterUserQuery) Read(reader io.Reader) UserQuery {
	return UserQuery{
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterOptionalStringINSTANCE.Read(reader),
		ffiConverterBoolINSTANCE.Read(reader),
	}
}

func (c ffiConverterUserQuery) Lower(value UserQuery) C.RustBuffer {
	return lowerIntoRustBuffer[UserQuery](c, value)
}

func (c ffiConverterUserQuery) LowerExternal(value UserQuery) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[UserQuery](c, value))
}

func (c ffiConverterUserQuery) Write(writer io.Writer, value UserQuery) {
	ffiConverterOptionalStringINSTANCE.Write(writer, value.Search)
	ffiConverterOptionalStringINSTANCE.Write(writer, value.GroupID)
	ffiConverterBoolINSTANCE.Write(writer, value.AdminOnly)
}

type ffiDestroyerUserQuery struct{}

func (_ ffiDestroyerUserQuery) Destroy(value UserQuery) {
	value.Destroy()
}

// What the generator makes by default.
type GeneratorType uint

const (
	GeneratorTypePassword   GeneratorType = 1
	GeneratorTypePassphrase GeneratorType = 2
)

type ffiConverterGeneratorType struct{}

var ffiConverterGeneratorTypeINSTANCE = ffiConverterGeneratorType{}

func (c ffiConverterGeneratorType) Lift(rb rustBufferI) GeneratorType {
	return liftFromRustBuffer[GeneratorType](c, rb)
}

func (c ffiConverterGeneratorType) Lower(value GeneratorType) C.RustBuffer {
	return lowerIntoRustBuffer[GeneratorType](c, value)
}

func (c ffiConverterGeneratorType) LowerExternal(value GeneratorType) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[GeneratorType](c, value))
}
func (ffiConverterGeneratorType) Read(reader io.Reader) GeneratorType {
	id := readInt32(reader)
	return GeneratorType(id)
}

func (ffiConverterGeneratorType) Write(writer io.Writer, value GeneratorType) {
	writeInt32(writer, int32(value))
}

type ffiDestroyerGeneratorType struct{}

func (_ ffiDestroyerGeneratorType) Destroy(value GeneratorType) {
}

// FFI-safe error type exposed to all target languages.
type PassboltError struct {
	err error
}

// Convience method to turn *PassboltError into error
// Avoiding treating nil pointer as non nil error interface
func (err *PassboltError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err PassboltError) Error() string {
	return fmt.Sprintf("PassboltError: %s", err.err.Error())
}

func (err PassboltError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrPassboltErrorTransport = fmt.Errorf("PassboltErrorTransport")
var ErrPassboltErrorAuth = fmt.Errorf("PassboltErrorAuth")
var ErrPassboltErrorCrypto = fmt.Errorf("PassboltErrorCrypto")
var ErrPassboltErrorAPI = fmt.Errorf("PassboltErrorApi")
var ErrPassboltErrorNotFound = fmt.Errorf("PassboltErrorNotFound")
var ErrPassboltErrorConfig = fmt.Errorf("PassboltErrorConfig")
var ErrPassboltErrorInvalidArgument = fmt.Errorf("PassboltErrorInvalidArgument")
var ErrPassboltErrorOther = fmt.Errorf("PassboltErrorOther")

// Variant structs
type PassboltErrorTransport struct {
	Reason string
}

func NewPassboltErrorTransport(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorTransport{
		Reason: reason}}
}

func (e PassboltErrorTransport) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorTransport) Error() string {
	return fmt.Sprint("Transport",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorTransport) Is(target error) bool {
	return target == ErrPassboltErrorTransport
}

type PassboltErrorAuth struct {
	Reason string
}

func NewPassboltErrorAuth(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorAuth{
		Reason: reason}}
}

func (e PassboltErrorAuth) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorAuth) Error() string {
	return fmt.Sprint("Auth",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorAuth) Is(target error) bool {
	return target == ErrPassboltErrorAuth
}

type PassboltErrorCrypto struct {
	Reason string
}

func NewPassboltErrorCrypto(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorCrypto{
		Reason: reason}}
}

func (e PassboltErrorCrypto) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorCrypto) Error() string {
	return fmt.Sprint("Crypto",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorCrypto) Is(target error) bool {
	return target == ErrPassboltErrorCrypto
}

type PassboltErrorAPI struct {
	Status uint16
	Reason string
}

func NewPassboltErrorAPI(
	status uint16,
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorAPI{
		Status: status,
		Reason: reason}}
}

func (e PassboltErrorAPI) destroy() {
	ffiDestroyerUint16{}.Destroy(e.Status)
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorAPI) Error() string {
	return fmt.Sprint("Api",
		": ",

		"Status=",
		err.Status,
		", ",
		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorAPI) Is(target error) bool {
	return target == ErrPassboltErrorAPI
}

type PassboltErrorNotFound struct {
	Reason string
}

func NewPassboltErrorNotFound(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorNotFound{
		Reason: reason}}
}

func (e PassboltErrorNotFound) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorNotFound) Error() string {
	return fmt.Sprint("NotFound",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorNotFound) Is(target error) bool {
	return target == ErrPassboltErrorNotFound
}

type PassboltErrorConfig struct {
	Reason string
}

func NewPassboltErrorConfig(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorConfig{
		Reason: reason}}
}

func (e PassboltErrorConfig) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorConfig) Error() string {
	return fmt.Sprint("Config",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorConfig) Is(target error) bool {
	return target == ErrPassboltErrorConfig
}

type PassboltErrorInvalidArgument struct {
	Reason string
}

func NewPassboltErrorInvalidArgument(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorInvalidArgument{
		Reason: reason}}
}

func (e PassboltErrorInvalidArgument) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorInvalidArgument) Error() string {
	return fmt.Sprint("InvalidArgument",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorInvalidArgument) Is(target error) bool {
	return target == ErrPassboltErrorInvalidArgument
}

type PassboltErrorOther struct {
	Reason string
}

func NewPassboltErrorOther(
	reason string,
) *PassboltError {
	return &PassboltError{err: &PassboltErrorOther{
		Reason: reason}}
}

func (e PassboltErrorOther) destroy() {
	ffiDestroyerString{}.Destroy(e.Reason)
}

func (err PassboltErrorOther) Error() string {
	return fmt.Sprint("Other",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self PassboltErrorOther) Is(target error) bool {
	return target == ErrPassboltErrorOther
}

type ffiConverterPassboltError struct{}

var ffiConverterPassboltErrorINSTANCE = ffiConverterPassboltError{}

func (c ffiConverterPassboltError) Lift(eb rustBufferI) *PassboltError {
	return liftFromRustBuffer[*PassboltError](c, eb)
}

func (c ffiConverterPassboltError) Lower(value *PassboltError) C.RustBuffer {
	return lowerIntoRustBuffer[*PassboltError](c, value)
}

func (c ffiConverterPassboltError) LowerExternal(value *PassboltError) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*PassboltError](c, value))
}

func (c ffiConverterPassboltError) Read(reader io.Reader) *PassboltError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &PassboltError{&PassboltErrorTransport{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 2:
		return &PassboltError{&PassboltErrorAuth{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 3:
		return &PassboltError{&PassboltErrorCrypto{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 4:
		return &PassboltError{&PassboltErrorAPI{
			Status: ffiConverterUint16INSTANCE.Read(reader),
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 5:
		return &PassboltError{&PassboltErrorNotFound{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 6:
		return &PassboltError{&PassboltErrorConfig{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 7:
		return &PassboltError{&PassboltErrorInvalidArgument{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	case 8:
		return &PassboltError{&PassboltErrorOther{
			Reason: ffiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterPassboltError.Read()", errorID))
	}
}

func (c ffiConverterPassboltError) Write(writer io.Writer, value *PassboltError) {
	switch variantValue := value.err.(type) {
	case *PassboltErrorTransport:
		writeInt32(writer, 1)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorAuth:
		writeInt32(writer, 2)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorCrypto:
		writeInt32(writer, 3)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorAPI:
		writeInt32(writer, 4)
		ffiConverterUint16INSTANCE.Write(writer, variantValue.Status)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorNotFound:
		writeInt32(writer, 5)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorConfig:
		writeInt32(writer, 6)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorInvalidArgument:
		writeInt32(writer, 7)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	case *PassboltErrorOther:
		writeInt32(writer, 8)
		ffiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterPassboltError.Write", value))
	}
}

type ffiDestroyerPassboltError struct{}

func (_ ffiDestroyerPassboltError) Destroy(value *PassboltError) {
	switch variantValue := value.err.(type) {
	case PassboltErrorTransport:
		variantValue.destroy()
	case PassboltErrorAuth:
		variantValue.destroy()
	case PassboltErrorCrypto:
		variantValue.destroy()
	case PassboltErrorAPI:
		variantValue.destroy()
	case PassboltErrorNotFound:
		variantValue.destroy()
	case PassboltErrorConfig:
		variantValue.destroy()
	case PassboltErrorInvalidArgument:
		variantValue.destroy()
	case PassboltErrorOther:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerPassboltError.Destroy", value))
	}
}

// The strength the extension shows for a secret.
type Strength uint

const (
	// No secret.
	StrengthNotAvailable Strength = 1
	// Under 60 bits.
	StrengthVeryWeak Strength = 2
	// From 60 bits.
	StrengthWeak Strength = 3
	// From 80 bits.
	StrengthFair Strength = 4
	// From 112 bits.
	StrengthStrong Strength = 5
	// From 128 bits.
	StrengthVeryStrong Strength = 6
)

type ffiConverterStrength struct{}

var ffiConverterStrengthINSTANCE = ffiConverterStrength{}

func (c ffiConverterStrength) Lift(rb rustBufferI) Strength {
	return liftFromRustBuffer[Strength](c, rb)
}

func (c ffiConverterStrength) Lower(value Strength) C.RustBuffer {
	return lowerIntoRustBuffer[Strength](c, value)
}

func (c ffiConverterStrength) LowerExternal(value Strength) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[Strength](c, value))
}
func (ffiConverterStrength) Read(reader io.Reader) Strength {
	id := readInt32(reader)
	return Strength(id)
}

func (ffiConverterStrength) Write(writer io.Writer, value Strength) {
	writeInt32(writer, int32(value))
}

type ffiDestroyerStrength struct{}

func (_ ffiDestroyerStrength) Destroy(value Strength) {
}

// The case of the words of a passphrase.
type WordCase uint

const (
	WordCaseLowercase WordCase = 1
	WordCaseUppercase WordCase = 2
	// The first letter of each word in capital.
	WordCaseCamelcase WordCase = 3
)

type ffiConverterWordCase struct{}

var ffiConverterWordCaseINSTANCE = ffiConverterWordCase{}

func (c ffiConverterWordCase) Lift(rb rustBufferI) WordCase {
	return liftFromRustBuffer[WordCase](c, rb)
}

func (c ffiConverterWordCase) Lower(value WordCase) C.RustBuffer {
	return lowerIntoRustBuffer[WordCase](c, value)
}

func (c ffiConverterWordCase) LowerExternal(value WordCase) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[WordCase](c, value))
}
func (ffiConverterWordCase) Read(reader io.Reader) WordCase {
	id := readInt32(reader)
	return WordCase(id)
}

func (ffiConverterWordCase) Write(writer io.Writer, value WordCase) {
	writeInt32(writer, int32(value))
}

type ffiDestroyerWordCase struct{}

func (_ ffiDestroyerWordCase) Destroy(value WordCase) {
}

type ffiConverterOptionalUint32 struct{}

var ffiConverterOptionalUint32INSTANCE = ffiConverterOptionalUint32{}

func (c ffiConverterOptionalUint32) Lift(rb rustBufferI) *uint32 {
	return liftFromRustBuffer[*uint32](c, rb)
}

func (_ ffiConverterOptionalUint32) Read(reader io.Reader) *uint32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterUint32INSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalUint32) Lower(value *uint32) C.RustBuffer {
	return lowerIntoRustBuffer[*uint32](c, value)
}

func (c ffiConverterOptionalUint32) LowerExternal(value *uint32) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*uint32](c, value))
}

func (_ ffiConverterOptionalUint32) Write(writer io.Writer, value *uint32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterUint32INSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalUint32 struct{}

func (_ ffiDestroyerOptionalUint32) Destroy(value *uint32) {
	if value != nil {
		ffiDestroyerUint32{}.Destroy(*value)
	}
}

type ffiConverterOptionalInt32 struct{}

var ffiConverterOptionalInt32INSTANCE = ffiConverterOptionalInt32{}

func (c ffiConverterOptionalInt32) Lift(rb rustBufferI) *int32 {
	return liftFromRustBuffer[*int32](c, rb)
}

func (_ ffiConverterOptionalInt32) Read(reader io.Reader) *int32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterInt32INSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalInt32) Lower(value *int32) C.RustBuffer {
	return lowerIntoRustBuffer[*int32](c, value)
}

func (c ffiConverterOptionalInt32) LowerExternal(value *int32) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*int32](c, value))
}

func (_ ffiConverterOptionalInt32) Write(writer io.Writer, value *int32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterInt32INSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalInt32 struct{}

func (_ ffiDestroyerOptionalInt32) Destroy(value *int32) {
	if value != nil {
		ffiDestroyerInt32{}.Destroy(*value)
	}
}

type ffiConverterOptionalUint64 struct{}

var ffiConverterOptionalUint64INSTANCE = ffiConverterOptionalUint64{}

func (c ffiConverterOptionalUint64) Lift(rb rustBufferI) *uint64 {
	return liftFromRustBuffer[*uint64](c, rb)
}

func (_ ffiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalUint64) Lower(value *uint64) C.RustBuffer {
	return lowerIntoRustBuffer[*uint64](c, value)
}

func (c ffiConverterOptionalUint64) LowerExternal(value *uint64) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*uint64](c, value))
}

func (_ ffiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalUint64 struct{}

func (_ ffiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		ffiDestroyerUint64{}.Destroy(*value)
	}
}

type ffiConverterOptionalBool struct{}

var ffiConverterOptionalBoolINSTANCE = ffiConverterOptionalBool{}

func (c ffiConverterOptionalBool) Lift(rb rustBufferI) *bool {
	return liftFromRustBuffer[*bool](c, rb)
}

func (_ ffiConverterOptionalBool) Read(reader io.Reader) *bool {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterBoolINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalBool) Lower(value *bool) C.RustBuffer {
	return lowerIntoRustBuffer[*bool](c, value)
}

func (c ffiConverterOptionalBool) LowerExternal(value *bool) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*bool](c, value))
}

func (_ ffiConverterOptionalBool) Write(writer io.Writer, value *bool) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterBoolINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalBool struct{}

func (_ ffiDestroyerOptionalBool) Destroy(value *bool) {
	if value != nil {
		ffiDestroyerBool{}.Destroy(*value)
	}
}

type ffiConverterOptionalString struct{}

var ffiConverterOptionalStringINSTANCE = ffiConverterOptionalString{}

func (c ffiConverterOptionalString) Lift(rb rustBufferI) *string {
	return liftFromRustBuffer[*string](c, rb)
}

func (_ ffiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return lowerIntoRustBuffer[*string](c, value)
}

func (c ffiConverterOptionalString) LowerExternal(value *string) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*string](c, value))
}

func (_ ffiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterStringINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalString struct{}

func (_ ffiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		ffiDestroyerString{}.Destroy(*value)
	}
}

type ffiConverterOptionalFavorite struct{}

var ffiConverterOptionalFavoriteINSTANCE = ffiConverterOptionalFavorite{}

func (c ffiConverterOptionalFavorite) Lift(rb rustBufferI) *Favorite {
	return liftFromRustBuffer[*Favorite](c, rb)
}

func (_ ffiConverterOptionalFavorite) Read(reader io.Reader) *Favorite {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterFavoriteINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalFavorite) Lower(value *Favorite) C.RustBuffer {
	return lowerIntoRustBuffer[*Favorite](c, value)
}

func (c ffiConverterOptionalFavorite) LowerExternal(value *Favorite) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*Favorite](c, value))
}

func (_ ffiConverterOptionalFavorite) Write(writer io.Writer, value *Favorite) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterFavoriteINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalFavorite struct{}

func (_ ffiDestroyerOptionalFavorite) Destroy(value *Favorite) {
	if value != nil {
		ffiDestroyerFavorite{}.Destroy(*value)
	}
}

type ffiConverterOptionalGpgKey struct{}

var ffiConverterOptionalGpgKeyINSTANCE = ffiConverterOptionalGpgKey{}

func (c ffiConverterOptionalGpgKey) Lift(rb rustBufferI) *GpgKey {
	return liftFromRustBuffer[*GpgKey](c, rb)
}

func (_ ffiConverterOptionalGpgKey) Read(reader io.Reader) *GpgKey {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterGpgKeyINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalGpgKey) Lower(value *GpgKey) C.RustBuffer {
	return lowerIntoRustBuffer[*GpgKey](c, value)
}

func (c ffiConverterOptionalGpgKey) LowerExternal(value *GpgKey) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*GpgKey](c, value))
}

func (_ ffiConverterOptionalGpgKey) Write(writer io.Writer, value *GpgKey) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterGpgKeyINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalGpgKey struct{}

func (_ ffiDestroyerOptionalGpgKey) Destroy(value *GpgKey) {
	if value != nil {
		ffiDestroyerGpgKey{}.Destroy(*value)
	}
}

type ffiConverterOptionalGroup struct{}

var ffiConverterOptionalGroupINSTANCE = ffiConverterOptionalGroup{}

func (c ffiConverterOptionalGroup) Lift(rb rustBufferI) *Group {
	return liftFromRustBuffer[*Group](c, rb)
}

func (_ ffiConverterOptionalGroup) Read(reader io.Reader) *Group {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterGroupINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalGroup) Lower(value *Group) C.RustBuffer {
	return lowerIntoRustBuffer[*Group](c, value)
}

func (c ffiConverterOptionalGroup) LowerExternal(value *Group) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*Group](c, value))
}

func (_ ffiConverterOptionalGroup) Write(writer io.Writer, value *Group) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterGroupINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalGroup struct{}

func (_ ffiDestroyerOptionalGroup) Destroy(value *Group) {
	if value != nil {
		ffiDestroyerGroup{}.Destroy(*value)
	}
}

type ffiConverterOptionalRole struct{}

var ffiConverterOptionalRoleINSTANCE = ffiConverterOptionalRole{}

func (c ffiConverterOptionalRole) Lift(rb rustBufferI) *Role {
	return liftFromRustBuffer[*Role](c, rb)
}

func (_ ffiConverterOptionalRole) Read(reader io.Reader) *Role {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterRoleINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalRole) Lower(value *Role) C.RustBuffer {
	return lowerIntoRustBuffer[*Role](c, value)
}

func (c ffiConverterOptionalRole) LowerExternal(value *Role) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*Role](c, value))
}

func (_ ffiConverterOptionalRole) Write(writer io.Writer, value *Role) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterRoleINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalRole struct{}

func (_ ffiDestroyerOptionalRole) Destroy(value *Role) {
	if value != nil {
		ffiDestroyerRole{}.Destroy(*value)
	}
}

type ffiConverterOptionalTotpData struct{}

var ffiConverterOptionalTotpDataINSTANCE = ffiConverterOptionalTotpData{}

func (c ffiConverterOptionalTotpData) Lift(rb rustBufferI) *TotpData {
	return liftFromRustBuffer[*TotpData](c, rb)
}

func (_ ffiConverterOptionalTotpData) Read(reader io.Reader) *TotpData {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterTotpDataINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalTotpData) Lower(value *TotpData) C.RustBuffer {
	return lowerIntoRustBuffer[*TotpData](c, value)
}

func (c ffiConverterOptionalTotpData) LowerExternal(value *TotpData) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*TotpData](c, value))
}

func (_ ffiConverterOptionalTotpData) Write(writer io.Writer, value *TotpData) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterTotpDataINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalTotpData struct{}

func (_ ffiDestroyerOptionalTotpData) Destroy(value *TotpData) {
	if value != nil {
		ffiDestroyerTotpData{}.Destroy(*value)
	}
}

type ffiConverterOptionalUser struct{}

var ffiConverterOptionalUserINSTANCE = ffiConverterOptionalUser{}

func (c ffiConverterOptionalUser) Lift(rb rustBufferI) *User {
	return liftFromRustBuffer[*User](c, rb)
}

func (_ ffiConverterOptionalUser) Read(reader io.Reader) *User {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterUserINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalUser) Lower(value *User) C.RustBuffer {
	return lowerIntoRustBuffer[*User](c, value)
}

func (c ffiConverterOptionalUser) LowerExternal(value *User) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*User](c, value))
}

func (_ ffiConverterOptionalUser) Write(writer io.Writer, value *User) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterUserINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalUser struct{}

func (_ ffiDestroyerOptionalUser) Destroy(value *User) {
	if value != nil {
		ffiDestroyerUser{}.Destroy(*value)
	}
}

type ffiConverterOptionalUserProfile struct{}

var ffiConverterOptionalUserProfileINSTANCE = ffiConverterOptionalUserProfile{}

func (c ffiConverterOptionalUserProfile) Lift(rb rustBufferI) *UserProfile {
	return liftFromRustBuffer[*UserProfile](c, rb)
}

func (_ ffiConverterOptionalUserProfile) Read(reader io.Reader) *UserProfile {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterUserProfileINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalUserProfile) Lower(value *UserProfile) C.RustBuffer {
	return lowerIntoRustBuffer[*UserProfile](c, value)
}

func (c ffiConverterOptionalUserProfile) LowerExternal(value *UserProfile) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*UserProfile](c, value))
}

func (_ ffiConverterOptionalUserProfile) Write(writer io.Writer, value *UserProfile) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterUserProfileINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalUserProfile struct{}

func (_ ffiDestroyerOptionalUserProfile) Destroy(value *UserProfile) {
	if value != nil {
		ffiDestroyerUserProfile{}.Destroy(*value)
	}
}

type ffiConverterOptionalWordCase struct{}

var ffiConverterOptionalWordCaseINSTANCE = ffiConverterOptionalWordCase{}

func (c ffiConverterOptionalWordCase) Lift(rb rustBufferI) *WordCase {
	return liftFromRustBuffer[*WordCase](c, rb)
}

func (_ ffiConverterOptionalWordCase) Read(reader io.Reader) *WordCase {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterWordCaseINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalWordCase) Lower(value *WordCase) C.RustBuffer {
	return lowerIntoRustBuffer[*WordCase](c, value)
}

func (c ffiConverterOptionalWordCase) LowerExternal(value *WordCase) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*WordCase](c, value))
}

func (_ ffiConverterOptionalWordCase) Write(writer io.Writer, value *WordCase) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterWordCaseINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalWordCase struct{}

func (_ ffiDestroyerOptionalWordCase) Destroy(value *WordCase) {
	if value != nil {
		ffiDestroyerWordCase{}.Destroy(*value)
	}
}

type ffiConverterOptionalSequenceString struct{}

var ffiConverterOptionalSequenceStringINSTANCE = ffiConverterOptionalSequenceString{}

func (c ffiConverterOptionalSequenceString) Lift(rb rustBufferI) *[]string {
	return liftFromRustBuffer[*[]string](c, rb)
}

func (_ ffiConverterOptionalSequenceString) Read(reader io.Reader) *[]string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := ffiConverterSequenceStringINSTANCE.Read(reader)
	return &temp
}

func (c ffiConverterOptionalSequenceString) Lower(value *[]string) C.RustBuffer {
	return lowerIntoRustBuffer[*[]string](c, value)
}

func (c ffiConverterOptionalSequenceString) LowerExternal(value *[]string) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[*[]string](c, value))
}

func (_ ffiConverterOptionalSequenceString) Write(writer io.Writer, value *[]string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		ffiConverterSequenceStringINSTANCE.Write(writer, *value)
	}
}

type ffiDestroyerOptionalSequenceString struct{}

func (_ ffiDestroyerOptionalSequenceString) Destroy(value *[]string) {
	if value != nil {
		ffiDestroyerSequenceString{}.Destroy(*value)
	}
}

type ffiConverterSequenceString struct{}

var ffiConverterSequenceStringINSTANCE = ffiConverterSequenceString{}

func (c ffiConverterSequenceString) Lift(rb rustBufferI) []string {
	return liftFromRustBuffer[[]string](c, rb)
}

func (c ffiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return lowerIntoRustBuffer[[]string](c, value)
}

func (c ffiConverterSequenceString) LowerExternal(value []string) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]string](c, value))
}

func (c ffiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterStringINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceString struct{}

func (ffiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		ffiDestroyerString{}.Destroy(value)
	}
}

type ffiConverterSequenceAro struct{}

var ffiConverterSequenceAroINSTANCE = ffiConverterSequenceAro{}

func (c ffiConverterSequenceAro) Lift(rb rustBufferI) []Aro {
	return liftFromRustBuffer[[]Aro](c, rb)
}

func (c ffiConverterSequenceAro) Read(reader io.Reader) []Aro {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Aro, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterAroINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceAro) Lower(value []Aro) C.RustBuffer {
	return lowerIntoRustBuffer[[]Aro](c, value)
}

func (c ffiConverterSequenceAro) LowerExternal(value []Aro) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Aro](c, value))
}

func (c ffiConverterSequenceAro) Write(writer io.Writer, value []Aro) {
	if len(value) > math.MaxInt32 {
		panic("[]Aro is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterAroINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceAro struct{}

func (ffiDestroyerSequenceAro) Destroy(sequence []Aro) {
	for _, value := range sequence {
		ffiDestroyerAro{}.Destroy(value)
	}
}

type ffiConverterSequenceComment struct{}

var ffiConverterSequenceCommentINSTANCE = ffiConverterSequenceComment{}

func (c ffiConverterSequenceComment) Lift(rb rustBufferI) []Comment {
	return liftFromRustBuffer[[]Comment](c, rb)
}

func (c ffiConverterSequenceComment) Read(reader io.Reader) []Comment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Comment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterCommentINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceComment) Lower(value []Comment) C.RustBuffer {
	return lowerIntoRustBuffer[[]Comment](c, value)
}

func (c ffiConverterSequenceComment) LowerExternal(value []Comment) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Comment](c, value))
}

func (c ffiConverterSequenceComment) Write(writer io.Writer, value []Comment) {
	if len(value) > math.MaxInt32 {
		panic("[]Comment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterCommentINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceComment struct{}

func (ffiDestroyerSequenceComment) Destroy(sequence []Comment) {
	for _, value := range sequence {
		ffiDestroyerComment{}.Destroy(value)
	}
}

type ffiConverterSequenceFolder struct{}

var ffiConverterSequenceFolderINSTANCE = ffiConverterSequenceFolder{}

func (c ffiConverterSequenceFolder) Lift(rb rustBufferI) []Folder {
	return liftFromRustBuffer[[]Folder](c, rb)
}

func (c ffiConverterSequenceFolder) Read(reader io.Reader) []Folder {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Folder, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterFolderINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceFolder) Lower(value []Folder) C.RustBuffer {
	return lowerIntoRustBuffer[[]Folder](c, value)
}

func (c ffiConverterSequenceFolder) LowerExternal(value []Folder) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Folder](c, value))
}

func (c ffiConverterSequenceFolder) Write(writer io.Writer, value []Folder) {
	if len(value) > math.MaxInt32 {
		panic("[]Folder is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterFolderINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceFolder struct{}

func (ffiDestroyerSequenceFolder) Destroy(sequence []Folder) {
	for _, value := range sequence {
		ffiDestroyerFolder{}.Destroy(value)
	}
}

type ffiConverterSequenceFolderTreeNode struct{}

var ffiConverterSequenceFolderTreeNodeINSTANCE = ffiConverterSequenceFolderTreeNode{}

func (c ffiConverterSequenceFolderTreeNode) Lift(rb rustBufferI) []FolderTreeNode {
	return liftFromRustBuffer[[]FolderTreeNode](c, rb)
}

func (c ffiConverterSequenceFolderTreeNode) Read(reader io.Reader) []FolderTreeNode {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FolderTreeNode, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterFolderTreeNodeINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceFolderTreeNode) Lower(value []FolderTreeNode) C.RustBuffer {
	return lowerIntoRustBuffer[[]FolderTreeNode](c, value)
}

func (c ffiConverterSequenceFolderTreeNode) LowerExternal(value []FolderTreeNode) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]FolderTreeNode](c, value))
}

func (c ffiConverterSequenceFolderTreeNode) Write(writer io.Writer, value []FolderTreeNode) {
	if len(value) > math.MaxInt32 {
		panic("[]FolderTreeNode is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterFolderTreeNodeINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceFolderTreeNode struct{}

func (ffiDestroyerSequenceFolderTreeNode) Destroy(sequence []FolderTreeNode) {
	for _, value := range sequence {
		ffiDestroyerFolderTreeNode{}.Destroy(value)
	}
}

type ffiConverterSequenceGroup struct{}

var ffiConverterSequenceGroupINSTANCE = ffiConverterSequenceGroup{}

func (c ffiConverterSequenceGroup) Lift(rb rustBufferI) []Group {
	return liftFromRustBuffer[[]Group](c, rb)
}

func (c ffiConverterSequenceGroup) Read(reader io.Reader) []Group {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Group, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterGroupINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceGroup) Lower(value []Group) C.RustBuffer {
	return lowerIntoRustBuffer[[]Group](c, value)
}

func (c ffiConverterSequenceGroup) LowerExternal(value []Group) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Group](c, value))
}

func (c ffiConverterSequenceGroup) Write(writer io.Writer, value []Group) {
	if len(value) > math.MaxInt32 {
		panic("[]Group is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterGroupINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceGroup struct{}

func (ffiDestroyerSequenceGroup) Destroy(sequence []Group) {
	for _, value := range sequence {
		ffiDestroyerGroup{}.Destroy(value)
	}
}

type ffiConverterSequenceGroupUser struct{}

var ffiConverterSequenceGroupUserINSTANCE = ffiConverterSequenceGroupUser{}

func (c ffiConverterSequenceGroupUser) Lift(rb rustBufferI) []GroupUser {
	return liftFromRustBuffer[[]GroupUser](c, rb)
}

func (c ffiConverterSequenceGroupUser) Read(reader io.Reader) []GroupUser {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]GroupUser, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterGroupUserINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceGroupUser) Lower(value []GroupUser) C.RustBuffer {
	return lowerIntoRustBuffer[[]GroupUser](c, value)
}

func (c ffiConverterSequenceGroupUser) LowerExternal(value []GroupUser) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]GroupUser](c, value))
}

func (c ffiConverterSequenceGroupUser) Write(writer io.Writer, value []GroupUser) {
	if len(value) > math.MaxInt32 {
		panic("[]GroupUser is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterGroupUserINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceGroupUser struct{}

func (ffiDestroyerSequenceGroupUser) Destroy(sequence []GroupUser) {
	for _, value := range sequence {
		ffiDestroyerGroupUser{}.Destroy(value)
	}
}

type ffiConverterSequenceManagedGroup struct{}

var ffiConverterSequenceManagedGroupINSTANCE = ffiConverterSequenceManagedGroup{}

func (c ffiConverterSequenceManagedGroup) Lift(rb rustBufferI) []ManagedGroup {
	return liftFromRustBuffer[[]ManagedGroup](c, rb)
}

func (c ffiConverterSequenceManagedGroup) Read(reader io.Reader) []ManagedGroup {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ManagedGroup, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterManagedGroupINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceManagedGroup) Lower(value []ManagedGroup) C.RustBuffer {
	return lowerIntoRustBuffer[[]ManagedGroup](c, value)
}

func (c ffiConverterSequenceManagedGroup) LowerExternal(value []ManagedGroup) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]ManagedGroup](c, value))
}

func (c ffiConverterSequenceManagedGroup) Write(writer io.Writer, value []ManagedGroup) {
	if len(value) > math.MaxInt32 {
		panic("[]ManagedGroup is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterManagedGroupINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceManagedGroup struct{}

func (ffiDestroyerSequenceManagedGroup) Destroy(sequence []ManagedGroup) {
	for _, value := range sequence {
		ffiDestroyerManagedGroup{}.Destroy(value)
	}
}

type ffiConverterSequenceOwnedItem struct{}

var ffiConverterSequenceOwnedItemINSTANCE = ffiConverterSequenceOwnedItem{}

func (c ffiConverterSequenceOwnedItem) Lift(rb rustBufferI) []OwnedItem {
	return liftFromRustBuffer[[]OwnedItem](c, rb)
}

func (c ffiConverterSequenceOwnedItem) Read(reader io.Reader) []OwnedItem {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]OwnedItem, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterOwnedItemINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceOwnedItem) Lower(value []OwnedItem) C.RustBuffer {
	return lowerIntoRustBuffer[[]OwnedItem](c, value)
}

func (c ffiConverterSequenceOwnedItem) LowerExternal(value []OwnedItem) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]OwnedItem](c, value))
}

func (c ffiConverterSequenceOwnedItem) Write(writer io.Writer, value []OwnedItem) {
	if len(value) > math.MaxInt32 {
		panic("[]OwnedItem is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterOwnedItemINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceOwnedItem struct{}

func (ffiDestroyerSequenceOwnedItem) Destroy(sequence []OwnedItem) {
	for _, value := range sequence {
		ffiDestroyerOwnedItem{}.Destroy(value)
	}
}

type ffiConverterSequencePermission struct{}

var ffiConverterSequencePermissionINSTANCE = ffiConverterSequencePermission{}

func (c ffiConverterSequencePermission) Lift(rb rustBufferI) []Permission {
	return liftFromRustBuffer[[]Permission](c, rb)
}

func (c ffiConverterSequencePermission) Read(reader io.Reader) []Permission {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Permission, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterPermissionINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequencePermission) Lower(value []Permission) C.RustBuffer {
	return lowerIntoRustBuffer[[]Permission](c, value)
}

func (c ffiConverterSequencePermission) LowerExternal(value []Permission) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Permission](c, value))
}

func (c ffiConverterSequencePermission) Write(writer io.Writer, value []Permission) {
	if len(value) > math.MaxInt32 {
		panic("[]Permission is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterPermissionINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequencePermission struct{}

func (ffiDestroyerSequencePermission) Destroy(sequence []Permission) {
	for _, value := range sequence {
		ffiDestroyerPermission{}.Destroy(value)
	}
}

type ffiConverterSequenceResource struct{}

var ffiConverterSequenceResourceINSTANCE = ffiConverterSequenceResource{}

func (c ffiConverterSequenceResource) Lift(rb rustBufferI) []Resource {
	return liftFromRustBuffer[[]Resource](c, rb)
}

func (c ffiConverterSequenceResource) Read(reader io.Reader) []Resource {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Resource, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterResourceINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceResource) Lower(value []Resource) C.RustBuffer {
	return lowerIntoRustBuffer[[]Resource](c, value)
}

func (c ffiConverterSequenceResource) LowerExternal(value []Resource) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Resource](c, value))
}

func (c ffiConverterSequenceResource) Write(writer io.Writer, value []Resource) {
	if len(value) > math.MaxInt32 {
		panic("[]Resource is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterResourceINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceResource struct{}

func (ffiDestroyerSequenceResource) Destroy(sequence []Resource) {
	for _, value := range sequence {
		ffiDestroyerResource{}.Destroy(value)
	}
}

type ffiConverterSequenceResourceType struct{}

var ffiConverterSequenceResourceTypeINSTANCE = ffiConverterSequenceResourceType{}

func (c ffiConverterSequenceResourceType) Lift(rb rustBufferI) []ResourceType {
	return liftFromRustBuffer[[]ResourceType](c, rb)
}

func (c ffiConverterSequenceResourceType) Read(reader io.Reader) []ResourceType {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ResourceType, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterResourceTypeINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceResourceType) Lower(value []ResourceType) C.RustBuffer {
	return lowerIntoRustBuffer[[]ResourceType](c, value)
}

func (c ffiConverterSequenceResourceType) LowerExternal(value []ResourceType) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]ResourceType](c, value))
}

func (c ffiConverterSequenceResourceType) Write(writer io.Writer, value []ResourceType) {
	if len(value) > math.MaxInt32 {
		panic("[]ResourceType is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterResourceTypeINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceResourceType struct{}

func (ffiDestroyerSequenceResourceType) Destroy(sequence []ResourceType) {
	for _, value := range sequence {
		ffiDestroyerResourceType{}.Destroy(value)
	}
}

type ffiConverterSequenceResourceView struct{}

var ffiConverterSequenceResourceViewINSTANCE = ffiConverterSequenceResourceView{}

func (c ffiConverterSequenceResourceView) Lift(rb rustBufferI) []ResourceView {
	return liftFromRustBuffer[[]ResourceView](c, rb)
}

func (c ffiConverterSequenceResourceView) Read(reader io.Reader) []ResourceView {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ResourceView, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterResourceViewINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceResourceView) Lower(value []ResourceView) C.RustBuffer {
	return lowerIntoRustBuffer[[]ResourceView](c, value)
}

func (c ffiConverterSequenceResourceView) LowerExternal(value []ResourceView) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]ResourceView](c, value))
}

func (c ffiConverterSequenceResourceView) Write(writer io.Writer, value []ResourceView) {
	if len(value) > math.MaxInt32 {
		panic("[]ResourceView is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterResourceViewINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceResourceView struct{}

func (ffiDestroyerSequenceResourceView) Destroy(sequence []ResourceView) {
	for _, value := range sequence {
		ffiDestroyerResourceView{}.Destroy(value)
	}
}

type ffiConverterSequenceSecret struct{}

var ffiConverterSequenceSecretINSTANCE = ffiConverterSequenceSecret{}

func (c ffiConverterSequenceSecret) Lift(rb rustBufferI) []Secret {
	return liftFromRustBuffer[[]Secret](c, rb)
}

func (c ffiConverterSequenceSecret) Read(reader io.Reader) []Secret {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Secret, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterSecretINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceSecret) Lower(value []Secret) C.RustBuffer {
	return lowerIntoRustBuffer[[]Secret](c, value)
}

func (c ffiConverterSequenceSecret) LowerExternal(value []Secret) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Secret](c, value))
}

func (c ffiConverterSequenceSecret) Write(writer io.Writer, value []Secret) {
	if len(value) > math.MaxInt32 {
		panic("[]Secret is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterSecretINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceSecret struct{}

func (ffiDestroyerSequenceSecret) Destroy(sequence []Secret) {
	for _, value := range sequence {
		ffiDestroyerSecret{}.Destroy(value)
	}
}

type ffiConverterSequenceTag struct{}

var ffiConverterSequenceTagINSTANCE = ffiConverterSequenceTag{}

func (c ffiConverterSequenceTag) Lift(rb rustBufferI) []Tag {
	return liftFromRustBuffer[[]Tag](c, rb)
}

func (c ffiConverterSequenceTag) Read(reader io.Reader) []Tag {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Tag, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterTagINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceTag) Lower(value []Tag) C.RustBuffer {
	return lowerIntoRustBuffer[[]Tag](c, value)
}

func (c ffiConverterSequenceTag) LowerExternal(value []Tag) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]Tag](c, value))
}

func (c ffiConverterSequenceTag) Write(writer io.Writer, value []Tag) {
	if len(value) > math.MaxInt32 {
		panic("[]Tag is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterTagINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceTag struct{}

func (ffiDestroyerSequenceTag) Destroy(sequence []Tag) {
	for _, value := range sequence {
		ffiDestroyerTag{}.Destroy(value)
	}
}

type ffiConverterSequenceUser struct{}

var ffiConverterSequenceUserINSTANCE = ffiConverterSequenceUser{}

func (c ffiConverterSequenceUser) Lift(rb rustBufferI) []User {
	return liftFromRustBuffer[[]User](c, rb)
}

func (c ffiConverterSequenceUser) Read(reader io.Reader) []User {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]User, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, ffiConverterUserINSTANCE.Read(reader))
	}
	return result
}

func (c ffiConverterSequenceUser) Lower(value []User) C.RustBuffer {
	return lowerIntoRustBuffer[[]User](c, value)
}

func (c ffiConverterSequenceUser) LowerExternal(value []User) externalCRustBuffer {
	return rustBufferFromC(lowerIntoRustBuffer[[]User](c, value))
}

func (c ffiConverterSequenceUser) Write(writer io.Writer, value []User) {
	if len(value) > math.MaxInt32 {
		panic("[]User is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		ffiConverterUserINSTANCE.Write(writer, item)
	}
}

type ffiDestroyerSequenceUser struct{}

func (ffiDestroyerSequenceUser) Destroy(sequence []User) {
	for _, value := range sequence {
		ffiDestroyerUser{}.Destroy(value)
	}
}

const (
	uniffiRustFuturePollReady      int8 = 0
	uniffiRustFuturePollMaybeReady int8 = 1
)

type rustFuturePollFunc func(C.uint64_t, C.UniffiRustFutureContinuationCallback, C.uint64_t)
type rustFutureCompleteFunc[T any] func(C.uint64_t, *C.RustCallStatus) T
type rustFutureFreeFunc func(C.uint64_t)

//export passbolt_uniffiFutureContinuationCallback
func passbolt_uniffiFutureContinuationCallback(data C.uint64_t, pollResult C.int8_t) {
	h := cgo.Handle(uintptr(data))
	waiter := h.Value().(chan int8)
	waiter <- int8(pollResult)
}

func uniffiRustCallAsync[E any, T any, F any](
	errConverter uniffiBufReader[*E],
	completeFunc rustFutureCompleteFunc[F],
	liftFunc func(F) T,
	rustFuture C.uint64_t,
	pollFunc rustFuturePollFunc,
	freeFunc rustFutureFreeFunc,
) (T, *E) {
	defer freeFunc(rustFuture)

	pollResult := int8(-1)
	waiter := make(chan int8, 1)

	chanHandle := cgo.NewHandle(waiter)
	defer chanHandle.Delete()

	for pollResult != uniffiRustFuturePollReady {
		pollFunc(
			rustFuture,
			(C.UniffiRustFutureContinuationCallback)(C.passbolt_uniffiFutureContinuationCallback),
			C.uint64_t(chanHandle),
		)
		pollResult = <-waiter
	}

	var goValue T
	var ffiValue F
	var err *E

	ffiValue, err = rustCallWithError(errConverter, func(status *C.RustCallStatus) F {
		return completeFunc(rustFuture, status)
	})
	if err != nil {
		return goValue, err
	}
	return liftFunc(ffiValue), nil
}

//export passbolt_uniffiFreeGorutine
func passbolt_uniffiFreeGorutine(data C.uint64_t) {
	handle := cgo.Handle(uintptr(data))
	defer handle.Delete()

	guard := handle.Value().(chan struct{})
	guard <- struct{}{}
}

// Decrypt a PGP-armored message with a private key.
func DecryptMessage(armoredMessage string, privateKeyArmored string, passphrase string) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_decrypt_message(ffiConverterStringINSTANCE.Lower(armoredMessage), ffiConverterStringINSTANCE.Lower(privateKeyArmored), ffiConverterStringINSTANCE.Lower(passphrase), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

// The policies of a server without settings: passwords of 18 characters by default.
func DefaultPasswordPolicies() PasswordPolicies {
	return ffiConverterPasswordPoliciesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_default_password_policies(_uniffiStatus),
		}
	}))
}

// Encrypt a plaintext message for one or more PGP public keys.
// Returns the PGP-armored ciphertext.
func EncryptMessage(plaintext []byte, publicKeysArmored []string) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_encrypt_message(ffiConverterBytesINSTANCE.Lower(plaintext), ffiConverterSequenceStringINSTANCE.Lower(publicKeysArmored), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// The server public key, to pin in [`LoginOptions::server_public_key`] once the user
// confirmed its fingerprint.
func FetchServerKey(serverURL string, tlsSkipVerify bool) (ServerKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_fetch_server_key(ffiConverterStringINSTANCE.Lower(serverURL), ffiConverterBoolINSTANCE.Lower(tlsSkipVerify), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ServerKey
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterServerKeyINSTANCE.Lift(_uniffiRV), nil
	}
}

// A passphrase of words of the EFF list following `settings`.
func GeneratePassphrase(settings PassphraseGeneratorSettings) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_generate_passphrase(ffiConverterPassphraseGeneratorSettingsINSTANCE.Lower(settings), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// A password following `settings`, as the extension generates it.
func GeneratePassword(settings PasswordGeneratorSettings) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_generate_password(ffiConverterPasswordGeneratorSettingsINSTANCE.Lower(settings), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// A PIN code of `length` digits, brought within 4 to 12.
func GeneratePinCode(length uint32) string {
	return ffiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_generate_pin_code(ffiConverterUint32INSTANCE.Lower(length), _uniffiStatus),
		}
	}))
}

// A secret from the default generator of `policies`, those of
// [`PassboltClient::get_password_policies`](crate::PassboltClient) for instance.
func GenerateSecret(policies PasswordPolicies) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_generate_secret(ffiConverterPasswordPoliciesINSTANCE.Lower(policies), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Parse a PGP private key and return its fingerprint (hex uppercase).
func GetKeyFingerprint(privateKeyArmored string) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltError](ffiConverterPassboltError{}, func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_get_key_fingerprint(ffiConverterStringINSTANCE.Lower(privateKeyArmored), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return ffiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// The entropy of `secret` in bits, measured as the extension does: as a passphrase when it
// is words of the list joined by one separator.
func SecretEntropy(secret string) float64 {
	return ffiConverterFloat64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.double {
		return C.uniffi_passbolt_ffi_fn_func_secret_entropy(ffiConverterStringINSTANCE.Lower(secret), _uniffiStatus)
	}))
}

// The strength the extension shows for `secret`.
func SecretStrength(secret string) Strength {
	return ffiConverterStrengthINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) rustBufferI {
		return goRustBuffer{
			inner: C.uniffi_passbolt_ffi_fn_func_secret_strength(ffiConverterStringINSTANCE.Lower(secret), _uniffiStatus),
		}
	}))
}
