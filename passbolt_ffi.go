
package passbolt_ffi

// #include <passbolt.h>
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"unsafe"
	"encoding/binary"
	"math"
	"runtime"
	"sync/atomic"
)



// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type ExternalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromC(b C.RustBuffer) ExternalCRustBuffer {
	return GoRustBuffer {
		inner: b,
	}
}

func CFromRustBuffer(b ExternalCRustBuffer) C.RustBuffer {
	return C.RustBuffer {
		capacity: C.uint64_t(b.Capacity()),
		len: C.uint64_t(b.Len()),
		data: (*C.uchar)(b.Data()),
	}
}

func RustBufferFromExternal(b ExternalCRustBuffer) GoRustBuffer {
	return GoRustBuffer {
		inner: C.RustBuffer {
			capacity: C.uint64_t(b.Capacity()),
			len: C.uint64_t(b.Len()),
			data: (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func( status *C.RustCallStatus) bool {
		C.ffi_passbolt_ffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
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
	foreign := C.ForeignBytes {
		len: C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}
	
	return rustCall(func( status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_passbolt_ffi_rustbuffer_from_bytes(foreign, status)
	})
}


type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
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

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
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



func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer { inner: status.errorBuf })
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer { inner: status.errorBuf })))
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
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer {
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

type NativeError interface {
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
	if checksum != 59843 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_decrypt_message: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_func_encrypt_message()
	})
	if checksum != 61737 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_encrypt_message: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_func_fetch_server_key()
	})
	if checksum != 6521 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_fetch_server_key: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_func_get_key_fingerprint()
	})
	if checksum != 18452 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_func_get_key_fingerprint: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_add_favorite()
	})
	if checksum != 32379 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_add_favorite: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_add_tag_to_resource()
	})
	if checksum != 54600 {
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
	if checksum != 32697 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_check_auth: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_check_password_pwned()
	})
	if checksum != 26033 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_check_password_pwned: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_comment()
	})
	if checksum != 41630 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_comment: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_folder()
	})
	if checksum != 26758 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_group()
	})
	if checksum != 61922 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_group: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_resource()
	})
	if checksum != 34579 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_create_user()
	})
	if checksum != 28670 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_create_user: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_decrypt_resource_secret()
	})
	if checksum != 39149 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_decrypt_resource_secret: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_comment()
	})
	if checksum != 52108 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_comment: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder()
	})
	if checksum != 29635 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder_with_content()
	})
	if checksum != 2592 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_folder_with_content: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group()
	})
	if checksum != 10011 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_dry_run()
	})
	if checksum != 12524 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_dry_run: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_with_transfer()
	})
	if checksum != 25239 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_group_with_transfer: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_password_expiry_settings()
	})
	if checksum != 33488 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_password_expiry_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resource()
	})
	if checksum != 1908 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resources()
	})
	if checksum != 29267 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_resources: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_tag()
	})
	if checksum != 64623 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_tag: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user()
	})
	if checksum != 45536 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_dry_run()
	})
	if checksum != 19165 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_dry_run: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_with_transfer()
	})
	if checksum != 43237 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_delete_user_with_transfer: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_comments()
	})
	if checksum != 55780 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_comments: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder()
	})
	if checksum != 43046 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_permissions()
	})
	if checksum != 39866 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_permissions: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_tree()
	})
	if checksum != 41747 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_folder_tree: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_group()
	})
	if checksum != 29073 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_group: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_me()
	})
	if checksum != 29731 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_me: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_keys_settings()
	})
	if checksum != 11033 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_keys_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_types_settings()
	})
	if checksum != 63148 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_metadata_types_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_expiry_settings()
	})
	if checksum != 52904 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_password_expiry_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource()
	})
	if checksum != 18104 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_permissions()
	})
	if checksum != 29445 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_permissions: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_view()
	})
	if checksum != 39035 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resource_view: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_resources_by_ids()
	})
	if checksum != 4566 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_resources_by_ids: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_tags()
	})
	if checksum != 37663 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_tags: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_get_user()
	})
	if checksum != 12029 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_get_user: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_group_delete_blockers()
	})
	if checksum != 7584 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_group_delete_blockers: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_keep_alive()
	})
	if checksum != 57751 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_keep_alive: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_folders()
	})
	if checksum != 43341 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_folders: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_groups()
	})
	if checksum != 61430 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_groups: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_types()
	})
	if checksum != 25707 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_types: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_views()
	})
	if checksum != 17643 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resource_views: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_resources()
	})
	if checksum != 40877 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_resources: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_list_users()
	})
	if checksum != 55830 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_list_users: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_logout()
	})
	if checksum != 58520 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_logout: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_metadata_key_fingerprint()
	})
	if checksum != 63744 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_metadata_key_fingerprint: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_move_folder()
	})
	if checksum != 8169 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_move_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_move_resource()
	})
	if checksum != 11295 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_move_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_remove_favorite()
	})
	if checksum != 34767 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_remove_favorite: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_rename_folder()
	})
	if checksum != 35790 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_rename_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_rename_tag()
	})
	if checksum != 12503 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_rename_tag: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_keys_settings()
	})
	if checksum != 21858 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_keys_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_types_settings()
	})
	if checksum != 57398 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_metadata_types_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_expiry_settings()
	})
	if checksum != 22901 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_save_password_expiry_settings: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_search_aros()
	})
	if checksum != 18856 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_search_aros: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_set_resource_tags()
	})
	if checksum != 22762 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_set_resource_tags: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_share_folder()
	})
	if checksum != 61044 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_share_folder: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_share_resource()
	})
	if checksum != 32552 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_share_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_group()
	})
	if checksum != 21615 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_group: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_resource()
	})
	if checksum != 1904 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_resource: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_update_user()
	})
	if checksum != 21814 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_method_passboltclient_update_user: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_method_passboltclient_user_delete_blockers()
	})
	if checksum != 11859 {
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
		return C.uniffi_passbolt_ffi_checksum_constructor_passboltclient_login()
	})
	if checksum != 4440 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_passboltclient_login: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_config()
	})
	if checksum != 26632 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_config: UniFFI API checksum mismatch")
	}
	}
	{
	checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
		return C.uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_options()
	})
	if checksum != 33674 {
		// If this happens try cleaning and rebuilding your project
		panic("passbolt_ffi: uniffi_passbolt_ffi_checksum_constructor_passboltclient_login_with_options: UniFFI API checksum mismatch")
	}
	}
}



type FfiConverterUint16 struct{}

var FfiConverterUint16INSTANCE = FfiConverterUint16{}

func (FfiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (FfiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (FfiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (FfiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type FfiDestroyerUint16 struct {}

func (FfiDestroyerUint16) Destroy(_ uint16) {}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct {}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct {}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct {}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct {}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
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

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c FfiConverterString) LowerExternal(value string) ExternalCRustBuffer {
	return RustBufferFromC(stringToRustBuffer(value))
}

func (FfiConverterString) Write(writer io.Writer, value string) {
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

type FfiDestroyerString struct {}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) LowerExternal(value []byte) ExternalCRustBuffer {
	return RustBufferFromC(c.Lower(value))
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
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

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
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

type FfiDestroyerBytes struct {}

func (FfiDestroyerBytes) Destroy(_ []byte) {}



// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer unsafe.Pointer
	callCounter atomic.Int64
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer
	freeFunction func(unsafe.Pointer, *C.RustCallStatus)
	destroyed atomic.Bool
}

func newFfiObject(
	pointer unsafe.Pointer, 
	cloneFunction func(unsafe.Pointer, *C.RustCallStatus) unsafe.Pointer, 
	freeFunction func(unsafe.Pointer, *C.RustCallStatus),
) FfiObject {
	return FfiObject {
		pointer: pointer,
		cloneFunction: cloneFunction, 
		freeFunction: freeFunction,
	}
}

func (ffiObject *FfiObject)incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter + 1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) unsafe.Pointer {
		return ffiObject.cloneFunction(ffiObject.pointer, status)
	})
}

func (ffiObject *FfiObject)decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject)destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject)freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}
// Authenticated Passbolt client for CRUD operations.
//
// All methods are synchronous at the FFI boundary; they block internally
// on the tokio runtime. Call from background threads on mobile platforms.
type PassboltClientInterface interface {
	// Add a resource to favorites.
	AddFavorite(resourceId string) (FfiFavorite, error)
	// Add a tag to a resource, keeping its other tags; returns the resource's tags.
	AddTagToResource(resourceId string, slug string) ([]FfiTag, error)
	// Get the server base URL.
	BaseUrl() string
	// Check if the session is still valid.
	CheckAuth() (bool, error)
	// Check if a password has been exposed in data breaches.
	// Returns the number of times found (0 = not breached).
	CheckPasswordPwned(password string) (uint64, error)
	// Create a comment on a resource.
	CreateComment(resourceId string, content string, parentId *string) (FfiComment, error)
	// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
	// parent's permissions.
	CreateFolder(name string, folderParentId *string) (FfiFolder, error)
	// Create a group; a manager is also a member.
	CreateGroup(name string, memberIds []string, managerIds []string) (FfiGroup, error)
	// Create a resource of any type from JSON: `{"name": …, "resource_type"?, "username"?,
	// "uris"?, "password"?, "totp"?, "note"?, "pin_code"?, "custom_fields"?,
	// "metadata_fields"?, "secret_fields"?, …}`. Returns the created resource.
	CreateResource(newResourceJson string) (FfiResource, error)
	// Create a user with the role named `role` (`user` or `admin`).
	CreateUser(username string, firstName string, lastName string, role string) (FfiUser, error)
	// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
	DecryptResourceSecret(resourceId string) (FfiSecretData, error)
	// Delete a comment.
	DeleteComment(id string) error
	// Delete a folder; its content moves to the root.
	DeleteFolder(id string) error
	// Delete a folder with its sub-folders and the resources the user may delete in them.
	DeleteFolderWithContent(id string) error
	// Delete a group.
	DeleteGroup(id string) error
	// Preview the impact of deleting a group.
	DeleteGroupDryRun(id string) (FfiGroupDeleteDryRun, error)
	// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
	// already has access to it.
	DeleteGroupWithTransfer(id string, successorId string) error
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
	DeleteUserDryRun(id string) (FfiUserDeleteDryRun, error)
	// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
	// group that already has access to it.
	DeleteUserWithTransfer(id string, successorId string) error
	// Get comments for a resource.
	GetComments(resourceId string) ([]FfiComment, error)
	// Get a single folder by ID.
	GetFolder(id string) (FfiFolder, error)
	// Get permissions for a folder.
	GetFolderPermissions(id string) ([]FfiPermission, error)
	// Build a folder tree from the flat folder list.
	GetFolderTree() ([]FfiFolderTreeNode, error)
	// Get a group by ID.
	GetGroup(id string) (FfiGroup, error)
	// Get the currently logged-in user.
	GetMe() (FfiUser, error)
	// How metadata keys are used in the organization.
	GetMetadataKeysSettings() (FfiMetadataKeysSettings, error)
	// Which metadata versions the organization creates and allows.
	GetMetadataTypesSettings() (FfiMetadataTypesSettings, error)
	// Get password expiry settings.
	GetPasswordExpirySettings() (FfiPasswordExpirySettings, error)
	// Get a single resource by ID.
	GetResource(id string) (FfiResource, error)
	// Get permissions for a resource.
	GetResourcePermissions(id string) ([]FfiPermission, error)
	// A resource with its v5 metadata and its secret decrypted, for every resource type, as
	// JSON: `name`, `username`, `uris`, `description`, `password`, `metadata`, `secret`…
	GetResourceView(id string) (string, error)
	// Get multiple resources by IDs.
	GetResourcesByIds(ids []string) ([]FfiResource, error)
	// List all tags.
	GetTags() ([]FfiTag, error)
	// Get a user by ID.
	GetUser(id string) (FfiUser, error)
	// What blocks deleting the group: what it alone owns.
	GroupDeleteBlockers(id string) (FfiDeleteBlockers, error)
	// Keep the session alive, as the browser extension does every few minutes.
	KeepAlive() error
	// List all folders.
	ListFolders(search *string) ([]FfiFolder, error)
	// List all groups.
	ListGroups() ([]FfiGroup, error)
	// The resource types of the server.
	ListResourceTypes() ([]FfiResourceType, error)
	// Resources with their v5 metadata decrypted, searched by their decrypted name, as a JSON
	// array; their secrets too with `with_secrets`. One that does not decrypt has an `error`.
	ListResourceViews(search *string, withSecrets bool) (string, error)
	// List resources with optional search and filters.
	ListResources(search *string, favoritesOnly bool, ownedByMe bool) ([]FfiResource, error)
	// List all users.
	ListUsers(search *string, groupId *string, adminOnly bool) ([]FfiUser, error)
	// Terminate the server-side session.
	Logout() 
	// The fingerprint of the active shared metadata key, to pin in
	// [`FfiLoginOptions::metadata_key_fingerprint`]; `None` without one.
	MetadataKeyFingerprint() (*string, error)
	// Move a folder into another one, or to the root without one.
	MoveFolder(id string, folderId *string) error
	// Move a resource into a folder, or to the root without one.
	MoveResource(id string, folderId *string) error
	// Remove a favorite.
	RemoveFavorite(favoriteId string) error
	// Rename a folder.
	RenameFolder(id string, name string) (FfiFolder, error)
	// Rename a tag.
	RenameTag(id string, slug string) (FfiTag, error)
	// Save the metadata keys settings (admin).
	SaveMetadataKeysSettings(settings FfiMetadataKeysSettings) (FfiMetadataKeysSettings, error)
	// Save the metadata types settings (admin).
	SaveMetadataTypesSettings(settings FfiMetadataTypesSettings) (FfiMetadataTypesSettings, error)
	// Create or update the password expiry settings (admin).
	SavePasswordExpirySettings(settings FfiPasswordExpirySettings) (FfiPasswordExpirySettings, error)
	// Search for users and groups (AROs) for sharing.
	SearchAros(search string) ([]FfiAro, error)
	// Replace all the tags of a resource; returns its tags.
	SetResourceTags(resourceId string, slugs []string) ([]FfiTag, error)
	// Share a folder, and with `with_content` the sub-folders and resources the user owns.
	ShareFolder(id string, userIds []string, groupIds []string, permissionType int32, withContent bool) error
	// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
	ShareResource(id string, userIds []string, groupIds []string, permissionType int32) error
	// Rename a group and change its members: the removed ones first, then the added ones,
	// who get the secrets of the group's resources. Giving a user the role they have, or
	// removing a non-member, is an error.
	UpdateGroup(id string, name *string, addMemberIds []string, addManagerIds []string, removeMemberIds []string) (FfiGroup, error)
	// Update a resource from the JSON of the fields to change; `"expired": null` clears the
	// expiry. Other fields keep their value.
	UpdateResource(id string, changesJson string) (FfiResource, error)
	// Update a user's names or role; `None` keeps the value.
	UpdateUser(id string, firstName *string, lastName *string, role *string) (FfiUser, error)
	// What blocks deleting the user: what they alone own or manage.
	UserDeleteBlockers(id string) (FfiDeleteBlockers, error)
	// Get the current user's ID.
	UserId() string
}
// Authenticated Passbolt client for CRUD operations.
//
// All methods are synchronous at the FFI boundary; they block internally
// on the tokio runtime. Call from background threads on mobile platforms.
type PassboltClient struct {
	ffiObject FfiObject
}


// Authenticate against a Passbolt server and return a client session.
func PassboltClientLogin(serverUrl string, privateKeyArmored string, passphrase string) (*PassboltClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_passbolt_ffi_fn_constructor_passboltclient_login(FfiConverterStringINSTANCE.Lower(serverUrl), FfiConverterStringINSTANCE.Lower(privateKeyArmored), FfiConverterStringINSTANCE.Lower(passphrase),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *PassboltClient
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterPassboltClientINSTANCE.Lift(_uniffiRV), nil
		}
}

// Authenticate with `options`, the pinned server and metadata keys among them.
func PassboltClientLoginWithConfig(serverUrl string, privateKeyArmored string, passphrase string, options FfiLoginOptions) (*PassboltClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_passbolt_ffi_fn_constructor_passboltclient_login_with_config(FfiConverterStringINSTANCE.Lower(serverUrl), FfiConverterStringINSTANCE.Lower(privateKeyArmored), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterFfiLoginOptionsINSTANCE.Lower(options),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *PassboltClient
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterPassboltClientINSTANCE.Lift(_uniffiRV), nil
		}
}

// Authenticate with advanced TLS/proxy options.
//
// `mfa_totp_token` is the base32 TOTP secret used to answer the MFA
// challenge without prompting; `None` or an empty string disables it.
func PassboltClientLoginWithOptions(serverUrl string, privateKeyArmored string, passphrase string, tlsSkipVerify bool, proxy *string, mfaTotpToken *string) (*PassboltClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_passbolt_ffi_fn_constructor_passboltclient_login_with_options(FfiConverterStringINSTANCE.Lower(serverUrl), FfiConverterStringINSTANCE.Lower(privateKeyArmored), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(tlsSkipVerify), FfiConverterOptionalStringINSTANCE.Lower(proxy), FfiConverterOptionalStringINSTANCE.Lower(mfaTotpToken),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *PassboltClient
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterPassboltClientINSTANCE.Lift(_uniffiRV), nil
		}
}



// Add a resource to favorites.
func (_self *PassboltClient) AddFavorite(resourceId string) (FfiFavorite, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_add_favorite(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiFavorite
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiFavoriteINSTANCE.Lift(_uniffiRV), nil
		}
}

// Add a tag to a resource, keeping its other tags; returns the resource's tags.
func (_self *PassboltClient) AddTagToResource(resourceId string, slug string) ([]FfiTag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_add_tag_to_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId), FfiConverterStringINSTANCE.Lower(slug),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiTag
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiTagINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get the server base URL.
func (_self *PassboltClient) BaseUrl() string {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_base_url(
		_pointer,_uniffiStatus),
	}
	}))
}

// Check if the session is still valid.
func (_self *PassboltClient) CheckAuth() (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_passbolt_ffi_fn_method_passboltclient_check_auth(
		_pointer,_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue bool
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
		}
}

// Check if a password has been exposed in data breaches.
// Returns the number of times found (0 = not breached).
func (_self *PassboltClient) CheckPasswordPwned(password string) (uint64, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_passbolt_ffi_fn_method_passboltclient_check_password_pwned(
		_pointer,FfiConverterStringINSTANCE.Lower(password),_uniffiStatus)
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue uint64
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterUint64INSTANCE.Lift(_uniffiRV), nil
		}
}

// Create a comment on a resource.
func (_self *PassboltClient) CreateComment(resourceId string, content string, parentId *string) (FfiComment, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_comment(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId), FfiConverterStringINSTANCE.Lower(content), FfiConverterOptionalStringINSTANCE.Lower(parentId),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiComment
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiCommentINSTANCE.Lift(_uniffiRV), nil
		}
}

// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
// parent's permissions.
func (_self *PassboltClient) CreateFolder(name string, folderParentId *string) (FfiFolder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(name), FfiConverterOptionalStringINSTANCE.Lower(folderParentId),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiFolder
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiFolderINSTANCE.Lift(_uniffiRV), nil
		}
}

// Create a group; a manager is also a member.
func (_self *PassboltClient) CreateGroup(name string, memberIds []string, managerIds []string) (FfiGroup, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_group(
		_pointer,FfiConverterStringINSTANCE.Lower(name), FfiConverterSequenceStringINSTANCE.Lower(memberIds), FfiConverterSequenceStringINSTANCE.Lower(managerIds),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiGroup
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiGroupINSTANCE.Lift(_uniffiRV), nil
		}
}

// Create a resource of any type from JSON: `{"name": …, "resource_type"?, "username"?,
// "uris"?, "password"?, "totp"?, "note"?, "pin_code"?, "custom_fields"?,
// "metadata_fields"?, "secret_fields"?, …}`. Returns the created resource.
func (_self *PassboltClient) CreateResource(newResourceJson string) (FfiResource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(newResourceJson),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiResource
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiResourceINSTANCE.Lift(_uniffiRV), nil
		}
}

// Create a user with the role named `role` (`user` or `admin`).
func (_self *PassboltClient) CreateUser(username string, firstName string, lastName string, role string) (FfiUser, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_create_user(
		_pointer,FfiConverterStringINSTANCE.Lower(username), FfiConverterStringINSTANCE.Lower(firstName), FfiConverterStringINSTANCE.Lower(lastName), FfiConverterStringINSTANCE.Lower(role),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiUser
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiUserINSTANCE.Lift(_uniffiRV), nil
		}
}

// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
func (_self *PassboltClient) DecryptResourceSecret(resourceId string) (FfiSecretData, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_decrypt_resource_secret(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiSecretData
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiSecretDataINSTANCE.Lift(_uniffiRV), nil
		}
}

// Delete a comment.
func (_self *PassboltClient) DeleteComment(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_comment(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a folder; its content moves to the root.
func (_self *PassboltClient) DeleteFolder(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a folder with its sub-folders and the resources the user may delete in them.
func (_self *PassboltClient) DeleteFolderWithContent(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_folder_with_content(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a group.
func (_self *PassboltClient) DeleteGroup(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Preview the impact of deleting a group.
func (_self *PassboltClient) DeleteGroupDryRun(id string) (FfiGroupDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group_dry_run(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiGroupDeleteDryRun
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiGroupDeleteDryRunINSTANCE.Lift(_uniffiRV), nil
		}
}

// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
// already has access to it.
func (_self *PassboltClient) DeleteGroupWithTransfer(id string, successorId string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_group_with_transfer(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(successorId),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete the password expiry settings (admin): the defaults apply again.
func (_self *PassboltClient) DeletePasswordExpirySettings(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_password_expiry_settings(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a resource.
func (_self *PassboltClient) DeleteResource(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Bulk delete resources.
func (_self *PassboltClient) DeleteResources(ids []string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_resources(
		_pointer,FfiConverterSequenceStringINSTANCE.Lower(ids),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a tag.
func (_self *PassboltClient) DeleteTag(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_tag(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Delete a user.
func (_self *PassboltClient) DeleteUser(id string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Preview the impact of deleting a user.
func (_self *PassboltClient) DeleteUserDryRun(id string) (FfiUserDeleteDryRun, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user_dry_run(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiUserDeleteDryRun
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiUserDeleteDryRunINSTANCE.Lift(_uniffiRV), nil
		}
}

// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
// group that already has access to it.
func (_self *PassboltClient) DeleteUserWithTransfer(id string, successorId string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_delete_user_with_transfer(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(successorId),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Get comments for a resource.
func (_self *PassboltClient) GetComments(resourceId string) ([]FfiComment, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_comments(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiComment
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiCommentINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get a single folder by ID.
func (_self *PassboltClient) GetFolder(id string) (FfiFolder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiFolder
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiFolderINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get permissions for a folder.
func (_self *PassboltClient) GetFolderPermissions(id string) ([]FfiPermission, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder_permissions(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiPermission
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiPermissionINSTANCE.Lift(_uniffiRV), nil
		}
}

// Build a folder tree from the flat folder list.
func (_self *PassboltClient) GetFolderTree() ([]FfiFolderTreeNode, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_folder_tree(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiFolderTreeNode
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiFolderTreeNodeINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get a group by ID.
func (_self *PassboltClient) GetGroup(id string) (FfiGroup, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_group(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiGroup
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiGroupINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get the currently logged-in user.
func (_self *PassboltClient) GetMe() (FfiUser, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_me(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiUser
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiUserINSTANCE.Lift(_uniffiRV), nil
		}
}

// How metadata keys are used in the organization.
func (_self *PassboltClient) GetMetadataKeysSettings() (FfiMetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_metadata_keys_settings(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiMetadataKeysSettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiMetadataKeysSettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Which metadata versions the organization creates and allows.
func (_self *PassboltClient) GetMetadataTypesSettings() (FfiMetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_metadata_types_settings(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiMetadataTypesSettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiMetadataTypesSettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get password expiry settings.
func (_self *PassboltClient) GetPasswordExpirySettings() (FfiPasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_password_expiry_settings(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiPasswordExpirySettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiPasswordExpirySettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get a single resource by ID.
func (_self *PassboltClient) GetResource(id string) (FfiResource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiResource
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiResourceINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get permissions for a resource.
func (_self *PassboltClient) GetResourcePermissions(id string) ([]FfiPermission, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource_permissions(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiPermission
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiPermissionINSTANCE.Lift(_uniffiRV), nil
		}
}

// A resource with its v5 metadata and its secret decrypted, for every resource type, as
// JSON: `name`, `username`, `uris`, `description`, `password`, `metadata`, `secret`…
func (_self *PassboltClient) GetResourceView(id string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resource_view(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue string
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get multiple resources by IDs.
func (_self *PassboltClient) GetResourcesByIds(ids []string) ([]FfiResource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_resources_by_ids(
		_pointer,FfiConverterSequenceStringINSTANCE.Lower(ids),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiResource
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiResourceINSTANCE.Lift(_uniffiRV), nil
		}
}

// List all tags.
func (_self *PassboltClient) GetTags() ([]FfiTag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_tags(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiTag
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiTagINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get a user by ID.
func (_self *PassboltClient) GetUser(id string) (FfiUser, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_get_user(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiUser
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiUserINSTANCE.Lift(_uniffiRV), nil
		}
}

// What blocks deleting the group: what it alone owns.
func (_self *PassboltClient) GroupDeleteBlockers(id string) (FfiDeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_group_delete_blockers(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiDeleteBlockers
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiDeleteBlockersINSTANCE.Lift(_uniffiRV), nil
		}
}

// Keep the session alive, as the browser extension does every few minutes.
func (_self *PassboltClient) KeepAlive() error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_keep_alive(
		_pointer,_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// List all folders.
func (_self *PassboltClient) ListFolders(search *string) ([]FfiFolder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_folders(
		_pointer,FfiConverterOptionalStringINSTANCE.Lower(search),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiFolder
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiFolderINSTANCE.Lift(_uniffiRV), nil
		}
}

// List all groups.
func (_self *PassboltClient) ListGroups() ([]FfiGroup, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_groups(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiGroup
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiGroupINSTANCE.Lift(_uniffiRV), nil
		}
}

// The resource types of the server.
func (_self *PassboltClient) ListResourceTypes() ([]FfiResourceType, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resource_types(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiResourceType
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiResourceTypeINSTANCE.Lift(_uniffiRV), nil
		}
}

// Resources with their v5 metadata decrypted, searched by their decrypted name, as a JSON
// array; their secrets too with `with_secrets`. One that does not decrypt has an `error`.
func (_self *PassboltClient) ListResourceViews(search *string, withSecrets bool) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resource_views(
		_pointer,FfiConverterOptionalStringINSTANCE.Lower(search), FfiConverterBoolINSTANCE.Lower(withSecrets),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue string
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
		}
}

// List resources with optional search and filters.
func (_self *PassboltClient) ListResources(search *string, favoritesOnly bool, ownedByMe bool) ([]FfiResource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_resources(
		_pointer,FfiConverterOptionalStringINSTANCE.Lower(search), FfiConverterBoolINSTANCE.Lower(favoritesOnly), FfiConverterBoolINSTANCE.Lower(ownedByMe),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiResource
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiResourceINSTANCE.Lift(_uniffiRV), nil
		}
}

// List all users.
func (_self *PassboltClient) ListUsers(search *string, groupId *string, adminOnly bool) ([]FfiUser, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_list_users(
		_pointer,FfiConverterOptionalStringINSTANCE.Lower(search), FfiConverterOptionalStringINSTANCE.Lower(groupId), FfiConverterBoolINSTANCE.Lower(adminOnly),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiUser
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiUserINSTANCE.Lift(_uniffiRV), nil
		}
}

// Terminate the server-side session.
func (_self *PassboltClient) Logout()  {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_logout(
		_pointer,_uniffiStatus)
		return false
	})
}

// The fingerprint of the active shared metadata key, to pin in
// [`FfiLoginOptions::metadata_key_fingerprint`]; `None` without one.
func (_self *PassboltClient) MetadataKeyFingerprint() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_metadata_key_fingerprint(
		_pointer,_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue *string
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterOptionalStringINSTANCE.Lift(_uniffiRV), nil
		}
}

// Move a folder into another one, or to the root without one.
func (_self *PassboltClient) MoveFolder(id string, folderId *string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_move_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterOptionalStringINSTANCE.Lower(folderId),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Move a resource into a folder, or to the root without one.
func (_self *PassboltClient) MoveResource(id string, folderId *string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_move_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterOptionalStringINSTANCE.Lower(folderId),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Remove a favorite.
func (_self *PassboltClient) RemoveFavorite(favoriteId string) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_remove_favorite(
		_pointer,FfiConverterStringINSTANCE.Lower(favoriteId),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Rename a folder.
func (_self *PassboltClient) RenameFolder(id string, name string) (FfiFolder, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_rename_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(name),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiFolder
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiFolderINSTANCE.Lift(_uniffiRV), nil
		}
}

// Rename a tag.
func (_self *PassboltClient) RenameTag(id string, slug string) (FfiTag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_rename_tag(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(slug),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiTag
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiTagINSTANCE.Lift(_uniffiRV), nil
		}
}

// Save the metadata keys settings (admin).
func (_self *PassboltClient) SaveMetadataKeysSettings(settings FfiMetadataKeysSettings) (FfiMetadataKeysSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_metadata_keys_settings(
		_pointer,FfiConverterFfiMetadataKeysSettingsINSTANCE.Lower(settings),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiMetadataKeysSettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiMetadataKeysSettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Save the metadata types settings (admin).
func (_self *PassboltClient) SaveMetadataTypesSettings(settings FfiMetadataTypesSettings) (FfiMetadataTypesSettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_metadata_types_settings(
		_pointer,FfiConverterFfiMetadataTypesSettingsINSTANCE.Lower(settings),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiMetadataTypesSettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiMetadataTypesSettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Create or update the password expiry settings (admin).
func (_self *PassboltClient) SavePasswordExpirySettings(settings FfiPasswordExpirySettings) (FfiPasswordExpirySettings, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_save_password_expiry_settings(
		_pointer,FfiConverterFfiPasswordExpirySettingsINSTANCE.Lower(settings),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiPasswordExpirySettings
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiPasswordExpirySettingsINSTANCE.Lift(_uniffiRV), nil
		}
}

// Search for users and groups (AROs) for sharing.
func (_self *PassboltClient) SearchAros(search string) ([]FfiAro, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_search_aros(
		_pointer,FfiConverterStringINSTANCE.Lower(search),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiAro
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiAroINSTANCE.Lift(_uniffiRV), nil
		}
}

// Replace all the tags of a resource; returns its tags.
func (_self *PassboltClient) SetResourceTags(resourceId string, slugs []string) ([]FfiTag, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_set_resource_tags(
		_pointer,FfiConverterStringINSTANCE.Lower(resourceId), FfiConverterSequenceStringINSTANCE.Lower(slugs),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []FfiTag
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterSequenceFfiTagINSTANCE.Lift(_uniffiRV), nil
		}
}

// Share a folder, and with `with_content` the sub-folders and resources the user owns.
func (_self *PassboltClient) ShareFolder(id string, userIds []string, groupIds []string, permissionType int32, withContent bool) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_share_folder(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterSequenceStringINSTANCE.Lower(userIds), FfiConverterSequenceStringINSTANCE.Lower(groupIds), FfiConverterInt32INSTANCE.Lower(permissionType), FfiConverterBoolINSTANCE.Lower(withContent),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
func (_self *PassboltClient) ShareResource(id string, userIds []string, groupIds []string, permissionType int32) error {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_passbolt_ffi_fn_method_passboltclient_share_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterSequenceStringINSTANCE.Lower(userIds), FfiConverterSequenceStringINSTANCE.Lower(groupIds), FfiConverterInt32INSTANCE.Lower(permissionType),_uniffiStatus)
		return false
	})
		return _uniffiErr.AsError()
}

// Rename a group and change its members: the removed ones first, then the added ones,
// who get the secrets of the group's resources. Giving a user the role they have, or
// removing a non-member, is an error.
func (_self *PassboltClient) UpdateGroup(id string, name *string, addMemberIds []string, addManagerIds []string, removeMemberIds []string) (FfiGroup, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_group(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterOptionalStringINSTANCE.Lower(name), FfiConverterSequenceStringINSTANCE.Lower(addMemberIds), FfiConverterSequenceStringINSTANCE.Lower(addManagerIds), FfiConverterSequenceStringINSTANCE.Lower(removeMemberIds),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiGroup
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiGroupINSTANCE.Lift(_uniffiRV), nil
		}
}

// Update a resource from the JSON of the fields to change; `"expired": null` clears the
// expiry. Other fields keep their value.
func (_self *PassboltClient) UpdateResource(id string, changesJson string) (FfiResource, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_resource(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(changesJson),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiResource
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiResourceINSTANCE.Lift(_uniffiRV), nil
		}
}

// Update a user's names or role; `None` keeps the value.
func (_self *PassboltClient) UpdateUser(id string, firstName *string, lastName *string, role *string) (FfiUser, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_update_user(
		_pointer,FfiConverterStringINSTANCE.Lower(id), FfiConverterOptionalStringINSTANCE.Lower(firstName), FfiConverterOptionalStringINSTANCE.Lower(lastName), FfiConverterOptionalStringINSTANCE.Lower(role),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiUser
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiUserINSTANCE.Lift(_uniffiRV), nil
		}
}

// What blocks deleting the user: what they alone own or manage.
func (_self *PassboltClient) UserDeleteBlockers(id string) (FfiDeleteBlockers, error) {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_user_delete_blockers(
		_pointer,FfiConverterStringINSTANCE.Lower(id),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiDeleteBlockers
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiDeleteBlockersINSTANCE.Lift(_uniffiRV), nil
		}
}

// Get the current user's ID.
func (_self *PassboltClient) UserId() string {
	_pointer := _self.ffiObject.incrementPointer("*PassboltClient")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_method_passboltclient_user_id(
		_pointer,_uniffiStatus),
	}
	}))
}
func (object *PassboltClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterPassboltClient struct {}

var FfiConverterPassboltClientINSTANCE = FfiConverterPassboltClient{}


func (c FfiConverterPassboltClient) Lift(pointer unsafe.Pointer) *PassboltClient {
	result := &PassboltClient {
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

func (c FfiConverterPassboltClient) Read(reader io.Reader) *PassboltClient {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterPassboltClient) Lower(value *PassboltClient) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*PassboltClient")
	defer value.ffiObject.decrementPointer()
	return pointer
	
}

func (c FfiConverterPassboltClient) Write(writer io.Writer, value *PassboltClient) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerPassboltClient struct {}

func (_ FfiDestroyerPassboltClient) Destroy(value *PassboltClient) {
		value.Destroy()
}




type FfiAro struct {
	Id string
	AroType *string
	Username *string
	Profile *FfiUserProfile
	Name *string
}

func (r *FfiAro) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.AroType);
		FfiDestroyerOptionalString{}.Destroy(r.Username);
		FfiDestroyerOptionalFfiUserProfile{}.Destroy(r.Profile);
		FfiDestroyerOptionalString{}.Destroy(r.Name);
}

type FfiConverterFfiAro struct {}

var FfiConverterFfiAroINSTANCE = FfiConverterFfiAro{}

func (c FfiConverterFfiAro) Lift(rb RustBufferI) FfiAro {
	return LiftFromRustBuffer[FfiAro](c, rb)
}

func (c FfiConverterFfiAro) Read(reader io.Reader) FfiAro {
	return FfiAro {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalFfiUserProfileINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiAro) Lower(value FfiAro) C.RustBuffer {
	return LowerIntoRustBuffer[FfiAro](c, value)
}

func (c FfiConverterFfiAro) LowerExternal(value FfiAro) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiAro](c, value))
}

func (c FfiConverterFfiAro) Write(writer io.Writer, value FfiAro) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.AroType);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Username);
		FfiConverterOptionalFfiUserProfileINSTANCE.Write(writer, value.Profile);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Name);
}

type FfiDestroyerFfiAro struct {}

func (_ FfiDestroyerFfiAro) Destroy(value FfiAro) {
	value.Destroy()
}

type FfiComment struct {
	Id string
	ParentId *string
	ForeignKey *string
	ForeignModel *string
	Content string
	Created *string
	Modified *string
	CreatedBy *string
	ModifiedBy *string
	Creator *FfiUser
}

func (r *FfiComment) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.ParentId);
		FfiDestroyerOptionalString{}.Destroy(r.ForeignKey);
		FfiDestroyerOptionalString{}.Destroy(r.ForeignModel);
		FfiDestroyerString{}.Destroy(r.Content);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalString{}.Destroy(r.CreatedBy);
		FfiDestroyerOptionalString{}.Destroy(r.ModifiedBy);
		FfiDestroyerOptionalFfiUser{}.Destroy(r.Creator);
}

type FfiConverterFfiComment struct {}

var FfiConverterFfiCommentINSTANCE = FfiConverterFfiComment{}

func (c FfiConverterFfiComment) Lift(rb RustBufferI) FfiComment {
	return LiftFromRustBuffer[FfiComment](c, rb)
}

func (c FfiConverterFfiComment) Read(reader io.Reader) FfiComment {
	return FfiComment {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalFfiUserINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiComment) Lower(value FfiComment) C.RustBuffer {
	return LowerIntoRustBuffer[FfiComment](c, value)
}

func (c FfiConverterFfiComment) LowerExternal(value FfiComment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiComment](c, value))
}

func (c FfiConverterFfiComment) Write(writer io.Writer, value FfiComment) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ParentId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ForeignKey);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ForeignModel);
		FfiConverterStringINSTANCE.Write(writer, value.Content);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy);
		FfiConverterOptionalFfiUserINSTANCE.Write(writer, value.Creator);
}

type FfiDestroyerFfiComment struct {}

func (_ FfiDestroyerFfiComment) Destroy(value FfiComment) {
	value.Destroy()
}

// What blocks deleting a user or a group: each item needs a new owner, each group a new
// manager.
type FfiDeleteBlockers struct {
	Resources []FfiOwnedItem
	Folders []FfiOwnedItem
	Groups []FfiManagedGroup
	// Groups the deleted user is the only member of: deleted with them.
	GroupsToDelete []string
}

func (r *FfiDeleteBlockers) Destroy() {
		FfiDestroyerSequenceFfiOwnedItem{}.Destroy(r.Resources);
		FfiDestroyerSequenceFfiOwnedItem{}.Destroy(r.Folders);
		FfiDestroyerSequenceFfiManagedGroup{}.Destroy(r.Groups);
		FfiDestroyerSequenceString{}.Destroy(r.GroupsToDelete);
}

type FfiConverterFfiDeleteBlockers struct {}

var FfiConverterFfiDeleteBlockersINSTANCE = FfiConverterFfiDeleteBlockers{}

func (c FfiConverterFfiDeleteBlockers) Lift(rb RustBufferI) FfiDeleteBlockers {
	return LiftFromRustBuffer[FfiDeleteBlockers](c, rb)
}

func (c FfiConverterFfiDeleteBlockers) Read(reader io.Reader) FfiDeleteBlockers {
	return FfiDeleteBlockers {
			FfiConverterSequenceFfiOwnedItemINSTANCE.Read(reader),
			FfiConverterSequenceFfiOwnedItemINSTANCE.Read(reader),
			FfiConverterSequenceFfiManagedGroupINSTANCE.Read(reader),
			FfiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiDeleteBlockers) Lower(value FfiDeleteBlockers) C.RustBuffer {
	return LowerIntoRustBuffer[FfiDeleteBlockers](c, value)
}

func (c FfiConverterFfiDeleteBlockers) LowerExternal(value FfiDeleteBlockers) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiDeleteBlockers](c, value))
}

func (c FfiConverterFfiDeleteBlockers) Write(writer io.Writer, value FfiDeleteBlockers) {
		FfiConverterSequenceFfiOwnedItemINSTANCE.Write(writer, value.Resources);
		FfiConverterSequenceFfiOwnedItemINSTANCE.Write(writer, value.Folders);
		FfiConverterSequenceFfiManagedGroupINSTANCE.Write(writer, value.Groups);
		FfiConverterSequenceStringINSTANCE.Write(writer, value.GroupsToDelete);
}

type FfiDestroyerFfiDeleteBlockers struct {}

func (_ FfiDestroyerFfiDeleteBlockers) Destroy(value FfiDeleteBlockers) {
	value.Destroy()
}

type FfiFavorite struct {
	Id *string
	ForeignModel *string
	ForeignKey *string
	Created *string
}

func (r *FfiFavorite) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.ForeignModel);
		FfiDestroyerOptionalString{}.Destroy(r.ForeignKey);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
}

type FfiConverterFfiFavorite struct {}

var FfiConverterFfiFavoriteINSTANCE = FfiConverterFfiFavorite{}

func (c FfiConverterFfiFavorite) Lift(rb RustBufferI) FfiFavorite {
	return LiftFromRustBuffer[FfiFavorite](c, rb)
}

func (c FfiConverterFfiFavorite) Read(reader io.Reader) FfiFavorite {
	return FfiFavorite {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiFavorite) Lower(value FfiFavorite) C.RustBuffer {
	return LowerIntoRustBuffer[FfiFavorite](c, value)
}

func (c FfiConverterFfiFavorite) LowerExternal(value FfiFavorite) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiFavorite](c, value))
}

func (c FfiConverterFfiFavorite) Write(writer io.Writer, value FfiFavorite) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ForeignModel);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ForeignKey);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
}

type FfiDestroyerFfiFavorite struct {}

func (_ FfiDestroyerFfiFavorite) Destroy(value FfiFavorite) {
	value.Destroy()
}

type FfiFolder struct {
	Id string
	Name string
	FolderParentId *string
	Created *string
	Modified *string
	CreatedBy *string
	ModifiedBy *string
	Personal *bool
	Permissions []FfiPermission
}

func (r *FfiFolder) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Name);
		FfiDestroyerOptionalString{}.Destroy(r.FolderParentId);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalString{}.Destroy(r.CreatedBy);
		FfiDestroyerOptionalString{}.Destroy(r.ModifiedBy);
		FfiDestroyerOptionalBool{}.Destroy(r.Personal);
		FfiDestroyerSequenceFfiPermission{}.Destroy(r.Permissions);
}

type FfiConverterFfiFolder struct {}

var FfiConverterFfiFolderINSTANCE = FfiConverterFfiFolder{}

func (c FfiConverterFfiFolder) Lift(rb RustBufferI) FfiFolder {
	return LiftFromRustBuffer[FfiFolder](c, rb)
}

func (c FfiConverterFfiFolder) Read(reader io.Reader) FfiFolder {
	return FfiFolder {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterSequenceFfiPermissionINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiFolder) Lower(value FfiFolder) C.RustBuffer {
	return LowerIntoRustBuffer[FfiFolder](c, value)
}

func (c FfiConverterFfiFolder) LowerExternal(value FfiFolder) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiFolder](c, value))
}

func (c FfiConverterFfiFolder) Write(writer io.Writer, value FfiFolder) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Name);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.Personal);
		FfiConverterSequenceFfiPermissionINSTANCE.Write(writer, value.Permissions);
}

type FfiDestroyerFfiFolder struct {}

func (_ FfiDestroyerFfiFolder) Destroy(value FfiFolder) {
	value.Destroy()
}

type FfiFolderQuery struct {
	Search *string
}

func (r *FfiFolderQuery) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Search);
}

type FfiConverterFfiFolderQuery struct {}

var FfiConverterFfiFolderQueryINSTANCE = FfiConverterFfiFolderQuery{}

func (c FfiConverterFfiFolderQuery) Lift(rb RustBufferI) FfiFolderQuery {
	return LiftFromRustBuffer[FfiFolderQuery](c, rb)
}

func (c FfiConverterFfiFolderQuery) Read(reader io.Reader) FfiFolderQuery {
	return FfiFolderQuery {
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiFolderQuery) Lower(value FfiFolderQuery) C.RustBuffer {
	return LowerIntoRustBuffer[FfiFolderQuery](c, value)
}

func (c FfiConverterFfiFolderQuery) LowerExternal(value FfiFolderQuery) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiFolderQuery](c, value))
}

func (c FfiConverterFfiFolderQuery) Write(writer io.Writer, value FfiFolderQuery) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Search);
}

type FfiDestroyerFfiFolderQuery struct {}

func (_ FfiDestroyerFfiFolderQuery) Destroy(value FfiFolderQuery) {
	value.Destroy()
}

type FfiFolderTreeNode struct {
	Folder FfiFolder
	Children []FfiFolderTreeNode
}

func (r *FfiFolderTreeNode) Destroy() {
		FfiDestroyerFfiFolder{}.Destroy(r.Folder);
		FfiDestroyerSequenceFfiFolderTreeNode{}.Destroy(r.Children);
}

type FfiConverterFfiFolderTreeNode struct {}

var FfiConverterFfiFolderTreeNodeINSTANCE = FfiConverterFfiFolderTreeNode{}

func (c FfiConverterFfiFolderTreeNode) Lift(rb RustBufferI) FfiFolderTreeNode {
	return LiftFromRustBuffer[FfiFolderTreeNode](c, rb)
}

func (c FfiConverterFfiFolderTreeNode) Read(reader io.Reader) FfiFolderTreeNode {
	return FfiFolderTreeNode {
			FfiConverterFfiFolderINSTANCE.Read(reader),
			FfiConverterSequenceFfiFolderTreeNodeINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiFolderTreeNode) Lower(value FfiFolderTreeNode) C.RustBuffer {
	return LowerIntoRustBuffer[FfiFolderTreeNode](c, value)
}

func (c FfiConverterFfiFolderTreeNode) LowerExternal(value FfiFolderTreeNode) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiFolderTreeNode](c, value))
}

func (c FfiConverterFfiFolderTreeNode) Write(writer io.Writer, value FfiFolderTreeNode) {
		FfiConverterFfiFolderINSTANCE.Write(writer, value.Folder);
		FfiConverterSequenceFfiFolderTreeNodeINSTANCE.Write(writer, value.Children);
}

type FfiDestroyerFfiFolderTreeNode struct {}

func (_ FfiDestroyerFfiFolderTreeNode) Destroy(value FfiFolderTreeNode) {
	value.Destroy()
}

type FfiGpgKey struct {
	Id *string
	UserId *string
	ArmoredKey *string
	Bits *uint32
	Fingerprint *string
	KeyCreated *string
}

func (r *FfiGpgKey) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.UserId);
		FfiDestroyerOptionalString{}.Destroy(r.ArmoredKey);
		FfiDestroyerOptionalUint32{}.Destroy(r.Bits);
		FfiDestroyerOptionalString{}.Destroy(r.Fingerprint);
		FfiDestroyerOptionalString{}.Destroy(r.KeyCreated);
}

type FfiConverterFfiGpgKey struct {}

var FfiConverterFfiGpgKeyINSTANCE = FfiConverterFfiGpgKey{}

func (c FfiConverterFfiGpgKey) Lift(rb RustBufferI) FfiGpgKey {
	return LiftFromRustBuffer[FfiGpgKey](c, rb)
}

func (c FfiConverterFfiGpgKey) Read(reader io.Reader) FfiGpgKey {
	return FfiGpgKey {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalUint32INSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiGpgKey) Lower(value FfiGpgKey) C.RustBuffer {
	return LowerIntoRustBuffer[FfiGpgKey](c, value)
}

func (c FfiConverterFfiGpgKey) LowerExternal(value FfiGpgKey) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiGpgKey](c, value))
}

func (c FfiConverterFfiGpgKey) Write(writer io.Writer, value FfiGpgKey) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.UserId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ArmoredKey);
		FfiConverterOptionalUint32INSTANCE.Write(writer, value.Bits);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Fingerprint);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.KeyCreated);
}

type FfiDestroyerFfiGpgKey struct {}

func (_ FfiDestroyerFfiGpgKey) Destroy(value FfiGpgKey) {
	value.Destroy()
}

type FfiGroup struct {
	Id string
	Name string
	Created *string
	Modified *string
	CreatedBy *string
	ModifiedBy *string
	Deleted *bool
	GroupsUsers []FfiGroupUser
}

func (r *FfiGroup) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Name);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalString{}.Destroy(r.CreatedBy);
		FfiDestroyerOptionalString{}.Destroy(r.ModifiedBy);
		FfiDestroyerOptionalBool{}.Destroy(r.Deleted);
		FfiDestroyerSequenceFfiGroupUser{}.Destroy(r.GroupsUsers);
}

type FfiConverterFfiGroup struct {}

var FfiConverterFfiGroupINSTANCE = FfiConverterFfiGroup{}

func (c FfiConverterFfiGroup) Lift(rb RustBufferI) FfiGroup {
	return LiftFromRustBuffer[FfiGroup](c, rb)
}

func (c FfiConverterFfiGroup) Read(reader io.Reader) FfiGroup {
	return FfiGroup {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterSequenceFfiGroupUserINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiGroup) Lower(value FfiGroup) C.RustBuffer {
	return LowerIntoRustBuffer[FfiGroup](c, value)
}

func (c FfiConverterFfiGroup) LowerExternal(value FfiGroup) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiGroup](c, value))
}

func (c FfiConverterFfiGroup) Write(writer io.Writer, value FfiGroup) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Name);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.Deleted);
		FfiConverterSequenceFfiGroupUserINSTANCE.Write(writer, value.GroupsUsers);
}

type FfiDestroyerFfiGroup struct {}

func (_ FfiDestroyerFfiGroup) Destroy(value FfiGroup) {
	value.Destroy()
}

type FfiGroupDeleteDryRun struct {
	ResourcesSoleGroupCount uint32
	FoldersSoleGroupCount uint32
}

func (r *FfiGroupDeleteDryRun) Destroy() {
		FfiDestroyerUint32{}.Destroy(r.ResourcesSoleGroupCount);
		FfiDestroyerUint32{}.Destroy(r.FoldersSoleGroupCount);
}

type FfiConverterFfiGroupDeleteDryRun struct {}

var FfiConverterFfiGroupDeleteDryRunINSTANCE = FfiConverterFfiGroupDeleteDryRun{}

func (c FfiConverterFfiGroupDeleteDryRun) Lift(rb RustBufferI) FfiGroupDeleteDryRun {
	return LiftFromRustBuffer[FfiGroupDeleteDryRun](c, rb)
}

func (c FfiConverterFfiGroupDeleteDryRun) Read(reader io.Reader) FfiGroupDeleteDryRun {
	return FfiGroupDeleteDryRun {
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiGroupDeleteDryRun) Lower(value FfiGroupDeleteDryRun) C.RustBuffer {
	return LowerIntoRustBuffer[FfiGroupDeleteDryRun](c, value)
}

func (c FfiConverterFfiGroupDeleteDryRun) LowerExternal(value FfiGroupDeleteDryRun) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiGroupDeleteDryRun](c, value))
}

func (c FfiConverterFfiGroupDeleteDryRun) Write(writer io.Writer, value FfiGroupDeleteDryRun) {
		FfiConverterUint32INSTANCE.Write(writer, value.ResourcesSoleGroupCount);
		FfiConverterUint32INSTANCE.Write(writer, value.FoldersSoleGroupCount);
}

type FfiDestroyerFfiGroupDeleteDryRun struct {}

func (_ FfiDestroyerFfiGroupDeleteDryRun) Destroy(value FfiGroupDeleteDryRun) {
	value.Destroy()
}

type FfiGroupUser struct {
	Id *string
	GroupId *string
	UserId *string
	IsAdmin *bool
	Created *string
}

func (r *FfiGroupUser) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.GroupId);
		FfiDestroyerOptionalString{}.Destroy(r.UserId);
		FfiDestroyerOptionalBool{}.Destroy(r.IsAdmin);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
}

type FfiConverterFfiGroupUser struct {}

var FfiConverterFfiGroupUserINSTANCE = FfiConverterFfiGroupUser{}

func (c FfiConverterFfiGroupUser) Lift(rb RustBufferI) FfiGroupUser {
	return LiftFromRustBuffer[FfiGroupUser](c, rb)
}

func (c FfiConverterFfiGroupUser) Read(reader io.Reader) FfiGroupUser {
	return FfiGroupUser {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiGroupUser) Lower(value FfiGroupUser) C.RustBuffer {
	return LowerIntoRustBuffer[FfiGroupUser](c, value)
}

func (c FfiConverterFfiGroupUser) LowerExternal(value FfiGroupUser) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiGroupUser](c, value))
}

func (c FfiConverterFfiGroupUser) Write(writer io.Writer, value FfiGroupUser) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.GroupId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.UserId);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.IsAdmin);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
}

type FfiDestroyerFfiGroupUser struct {}

func (_ FfiDestroyerFfiGroupUser) Destroy(value FfiGroupUser) {
	value.Destroy()
}

// How to log in, beyond the credentials.
type FfiLoginOptions struct {
	TlsSkipVerify bool
	Proxy *string
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
	ClientKeyPem *string
}

func (r *FfiLoginOptions) Destroy() {
		FfiDestroyerBool{}.Destroy(r.TlsSkipVerify);
		FfiDestroyerOptionalString{}.Destroy(r.Proxy);
		FfiDestroyerOptionalString{}.Destroy(r.MfaTotpToken);
		FfiDestroyerOptionalString{}.Destroy(r.ServerPublicKey);
		FfiDestroyerOptionalString{}.Destroy(r.MetadataKeyFingerprint);
		FfiDestroyerOptionalUint64{}.Destroy(r.TimeoutSeconds);
		FfiDestroyerOptionalString{}.Destroy(r.ClientCertificatePem);
		FfiDestroyerOptionalString{}.Destroy(r.ClientKeyPem);
}

type FfiConverterFfiLoginOptions struct {}

var FfiConverterFfiLoginOptionsINSTANCE = FfiConverterFfiLoginOptions{}

func (c FfiConverterFfiLoginOptions) Lift(rb RustBufferI) FfiLoginOptions {
	return LiftFromRustBuffer[FfiLoginOptions](c, rb)
}

func (c FfiConverterFfiLoginOptions) Read(reader io.Reader) FfiLoginOptions {
	return FfiLoginOptions {
			FfiConverterBoolINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiLoginOptions) Lower(value FfiLoginOptions) C.RustBuffer {
	return LowerIntoRustBuffer[FfiLoginOptions](c, value)
}

func (c FfiConverterFfiLoginOptions) LowerExternal(value FfiLoginOptions) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiLoginOptions](c, value))
}

func (c FfiConverterFfiLoginOptions) Write(writer io.Writer, value FfiLoginOptions) {
		FfiConverterBoolINSTANCE.Write(writer, value.TlsSkipVerify);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Proxy);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.MfaTotpToken);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ServerPublicKey);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyFingerprint);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.TimeoutSeconds);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ClientCertificatePem);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ClientKeyPem);
}

type FfiDestroyerFfiLoginOptions struct {}

func (_ FfiDestroyerFfiLoginOptions) Destroy(value FfiLoginOptions) {
	value.Destroy()
}

// A group with other members that only the deleted user manages, with its memberships.
type FfiManagedGroup struct {
	Id string
	Name string
	GroupsUsers []FfiGroupUser
}

func (r *FfiManagedGroup) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Name);
		FfiDestroyerSequenceFfiGroupUser{}.Destroy(r.GroupsUsers);
}

type FfiConverterFfiManagedGroup struct {}

var FfiConverterFfiManagedGroupINSTANCE = FfiConverterFfiManagedGroup{}

func (c FfiConverterFfiManagedGroup) Lift(rb RustBufferI) FfiManagedGroup {
	return LiftFromRustBuffer[FfiManagedGroup](c, rb)
}

func (c FfiConverterFfiManagedGroup) Read(reader io.Reader) FfiManagedGroup {
	return FfiManagedGroup {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterSequenceFfiGroupUserINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiManagedGroup) Lower(value FfiManagedGroup) C.RustBuffer {
	return LowerIntoRustBuffer[FfiManagedGroup](c, value)
}

func (c FfiConverterFfiManagedGroup) LowerExternal(value FfiManagedGroup) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiManagedGroup](c, value))
}

func (c FfiConverterFfiManagedGroup) Write(writer io.Writer, value FfiManagedGroup) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Name);
		FfiConverterSequenceFfiGroupUserINSTANCE.Write(writer, value.GroupsUsers);
}

type FfiDestroyerFfiManagedGroup struct {}

func (_ FfiDestroyerFfiManagedGroup) Destroy(value FfiManagedGroup) {
	value.Destroy()
}

// How metadata keys are used in the organization (admin settings).
type FfiMetadataKeysSettings struct {
	AllowUsageOfPersonalKeys *bool
	ZeroKnowledgeKeyShare *bool
}

func (r *FfiMetadataKeysSettings) Destroy() {
		FfiDestroyerOptionalBool{}.Destroy(r.AllowUsageOfPersonalKeys);
		FfiDestroyerOptionalBool{}.Destroy(r.ZeroKnowledgeKeyShare);
}

type FfiConverterFfiMetadataKeysSettings struct {}

var FfiConverterFfiMetadataKeysSettingsINSTANCE = FfiConverterFfiMetadataKeysSettings{}

func (c FfiConverterFfiMetadataKeysSettings) Lift(rb RustBufferI) FfiMetadataKeysSettings {
	return LiftFromRustBuffer[FfiMetadataKeysSettings](c, rb)
}

func (c FfiConverterFfiMetadataKeysSettings) Read(reader io.Reader) FfiMetadataKeysSettings {
	return FfiMetadataKeysSettings {
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiMetadataKeysSettings) Lower(value FfiMetadataKeysSettings) C.RustBuffer {
	return LowerIntoRustBuffer[FfiMetadataKeysSettings](c, value)
}

func (c FfiConverterFfiMetadataKeysSettings) LowerExternal(value FfiMetadataKeysSettings) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiMetadataKeysSettings](c, value))
}

func (c FfiConverterFfiMetadataKeysSettings) Write(writer io.Writer, value FfiMetadataKeysSettings) {
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowUsageOfPersonalKeys);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.ZeroKnowledgeKeyShare);
}

type FfiDestroyerFfiMetadataKeysSettings struct {}

func (_ FfiDestroyerFfiMetadataKeysSettings) Destroy(value FfiMetadataKeysSettings) {
	value.Destroy()
}

// Which metadata versions the organization creates and allows (admin settings).
type FfiMetadataTypesSettings struct {
	DefaultResourceTypes *string
	DefaultFolderType *string
	DefaultTagType *string
	DefaultCommentType *string
	AllowCreationOfV5Resources *bool
	AllowCreationOfV5Folders *bool
	AllowCreationOfV5Tags *bool
	AllowCreationOfV5Comments *bool
	AllowCreationOfV4Resources *bool
	AllowCreationOfV4Folders *bool
	AllowCreationOfV4Tags *bool
	AllowCreationOfV4Comments *bool
}

func (r *FfiMetadataTypesSettings) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.DefaultResourceTypes);
		FfiDestroyerOptionalString{}.Destroy(r.DefaultFolderType);
		FfiDestroyerOptionalString{}.Destroy(r.DefaultTagType);
		FfiDestroyerOptionalString{}.Destroy(r.DefaultCommentType);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Resources);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Folders);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Tags);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV5Comments);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Resources);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Folders);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Tags);
		FfiDestroyerOptionalBool{}.Destroy(r.AllowCreationOfV4Comments);
}

type FfiConverterFfiMetadataTypesSettings struct {}

var FfiConverterFfiMetadataTypesSettingsINSTANCE = FfiConverterFfiMetadataTypesSettings{}

func (c FfiConverterFfiMetadataTypesSettings) Lift(rb RustBufferI) FfiMetadataTypesSettings {
	return LiftFromRustBuffer[FfiMetadataTypesSettings](c, rb)
}

func (c FfiConverterFfiMetadataTypesSettings) Read(reader io.Reader) FfiMetadataTypesSettings {
	return FfiMetadataTypesSettings {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiMetadataTypesSettings) Lower(value FfiMetadataTypesSettings) C.RustBuffer {
	return LowerIntoRustBuffer[FfiMetadataTypesSettings](c, value)
}

func (c FfiConverterFfiMetadataTypesSettings) LowerExternal(value FfiMetadataTypesSettings) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiMetadataTypesSettings](c, value))
}

func (c FfiConverterFfiMetadataTypesSettings) Write(writer io.Writer, value FfiMetadataTypesSettings) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.DefaultResourceTypes);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.DefaultFolderType);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.DefaultTagType);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.DefaultCommentType);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Resources);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Folders);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Tags);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV5Comments);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Resources);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Folders);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Tags);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AllowCreationOfV4Comments);
}

type FfiDestroyerFfiMetadataTypesSettings struct {}

func (_ FfiDestroyerFfiMetadataTypesSettings) Destroy(value FfiMetadataTypesSettings) {
	value.Destroy()
}

// A shared resource or folder only the deleted user or group owns, with its permissions.
type FfiOwnedItem struct {
	Id string
	Permissions []FfiPermission
}

func (r *FfiOwnedItem) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerSequenceFfiPermission{}.Destroy(r.Permissions);
}

type FfiConverterFfiOwnedItem struct {}

var FfiConverterFfiOwnedItemINSTANCE = FfiConverterFfiOwnedItem{}

func (c FfiConverterFfiOwnedItem) Lift(rb RustBufferI) FfiOwnedItem {
	return LiftFromRustBuffer[FfiOwnedItem](c, rb)
}

func (c FfiConverterFfiOwnedItem) Read(reader io.Reader) FfiOwnedItem {
	return FfiOwnedItem {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterSequenceFfiPermissionINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiOwnedItem) Lower(value FfiOwnedItem) C.RustBuffer {
	return LowerIntoRustBuffer[FfiOwnedItem](c, value)
}

func (c FfiConverterFfiOwnedItem) LowerExternal(value FfiOwnedItem) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiOwnedItem](c, value))
}

func (c FfiConverterFfiOwnedItem) Write(writer io.Writer, value FfiOwnedItem) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterSequenceFfiPermissionINSTANCE.Write(writer, value.Permissions);
}

type FfiDestroyerFfiOwnedItem struct {}

func (_ FfiDestroyerFfiOwnedItem) Destroy(value FfiOwnedItem) {
	value.Destroy()
}

type FfiPasswordExpirySettings struct {
	Id *string
	DefaultExpiryPeriodDays *uint32
	PolicyOverride *bool
	AutomaticExpiry *bool
	AutomaticUpdate *bool
}

func (r *FfiPasswordExpirySettings) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalUint32{}.Destroy(r.DefaultExpiryPeriodDays);
		FfiDestroyerOptionalBool{}.Destroy(r.PolicyOverride);
		FfiDestroyerOptionalBool{}.Destroy(r.AutomaticExpiry);
		FfiDestroyerOptionalBool{}.Destroy(r.AutomaticUpdate);
}

type FfiConverterFfiPasswordExpirySettings struct {}

var FfiConverterFfiPasswordExpirySettingsINSTANCE = FfiConverterFfiPasswordExpirySettings{}

func (c FfiConverterFfiPasswordExpirySettings) Lift(rb RustBufferI) FfiPasswordExpirySettings {
	return LiftFromRustBuffer[FfiPasswordExpirySettings](c, rb)
}

func (c FfiConverterFfiPasswordExpirySettings) Read(reader io.Reader) FfiPasswordExpirySettings {
	return FfiPasswordExpirySettings {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalUint32INSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiPasswordExpirySettings) Lower(value FfiPasswordExpirySettings) C.RustBuffer {
	return LowerIntoRustBuffer[FfiPasswordExpirySettings](c, value)
}

func (c FfiConverterFfiPasswordExpirySettings) LowerExternal(value FfiPasswordExpirySettings) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiPasswordExpirySettings](c, value))
}

func (c FfiConverterFfiPasswordExpirySettings) Write(writer io.Writer, value FfiPasswordExpirySettings) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalUint32INSTANCE.Write(writer, value.DefaultExpiryPeriodDays);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.PolicyOverride);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AutomaticExpiry);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.AutomaticUpdate);
}

type FfiDestroyerFfiPasswordExpirySettings struct {}

func (_ FfiDestroyerFfiPasswordExpirySettings) Destroy(value FfiPasswordExpirySettings) {
	value.Destroy()
}

type FfiPermission struct {
	Id *string
	Aco *string
	AcoForeignKey *string
	Aro *string
	AroForeignKey *string
	PermissionType *int32
	Created *string
	Modified *string
	User *FfiUser
	Group *FfiGroup
}

func (r *FfiPermission) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.Aco);
		FfiDestroyerOptionalString{}.Destroy(r.AcoForeignKey);
		FfiDestroyerOptionalString{}.Destroy(r.Aro);
		FfiDestroyerOptionalString{}.Destroy(r.AroForeignKey);
		FfiDestroyerOptionalInt32{}.Destroy(r.PermissionType);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalFfiUser{}.Destroy(r.User);
		FfiDestroyerOptionalFfiGroup{}.Destroy(r.Group);
}

type FfiConverterFfiPermission struct {}

var FfiConverterFfiPermissionINSTANCE = FfiConverterFfiPermission{}

func (c FfiConverterFfiPermission) Lift(rb RustBufferI) FfiPermission {
	return LiftFromRustBuffer[FfiPermission](c, rb)
}

func (c FfiConverterFfiPermission) Read(reader io.Reader) FfiPermission {
	return FfiPermission {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalInt32INSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalFfiUserINSTANCE.Read(reader),
			FfiConverterOptionalFfiGroupINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiPermission) Lower(value FfiPermission) C.RustBuffer {
	return LowerIntoRustBuffer[FfiPermission](c, value)
}

func (c FfiConverterFfiPermission) LowerExternal(value FfiPermission) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiPermission](c, value))
}

func (c FfiConverterFfiPermission) Write(writer io.Writer, value FfiPermission) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Aco);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.AcoForeignKey);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Aro);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.AroForeignKey);
		FfiConverterOptionalInt32INSTANCE.Write(writer, value.PermissionType);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalFfiUserINSTANCE.Write(writer, value.User);
		FfiConverterOptionalFfiGroupINSTANCE.Write(writer, value.Group);
}

type FfiDestroyerFfiPermission struct {}

func (_ FfiDestroyerFfiPermission) Destroy(value FfiPermission) {
	value.Destroy()
}

type FfiResource struct {
	Id string
	Name string
	Username *string
	Uri *string
	Description *string
	FolderParentId *string
	ResourceTypeId *string
	Created *string
	Modified *string
	CreatedBy *string
	ModifiedBy *string
	Personal *bool
	Favorite *FfiFavorite
	Secrets []FfiSecret
	Permissions []FfiPermission
	Expired *string
	// v5 only: PGP-armored encrypted metadata.
	Metadata *string
	MetadataKeyId *string
	MetadataKeyType *string
}

func (r *FfiResource) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Name);
		FfiDestroyerOptionalString{}.Destroy(r.Username);
		FfiDestroyerOptionalString{}.Destroy(r.Uri);
		FfiDestroyerOptionalString{}.Destroy(r.Description);
		FfiDestroyerOptionalString{}.Destroy(r.FolderParentId);
		FfiDestroyerOptionalString{}.Destroy(r.ResourceTypeId);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalString{}.Destroy(r.CreatedBy);
		FfiDestroyerOptionalString{}.Destroy(r.ModifiedBy);
		FfiDestroyerOptionalBool{}.Destroy(r.Personal);
		FfiDestroyerOptionalFfiFavorite{}.Destroy(r.Favorite);
		FfiDestroyerSequenceFfiSecret{}.Destroy(r.Secrets);
		FfiDestroyerSequenceFfiPermission{}.Destroy(r.Permissions);
		FfiDestroyerOptionalString{}.Destroy(r.Expired);
		FfiDestroyerOptionalString{}.Destroy(r.Metadata);
		FfiDestroyerOptionalString{}.Destroy(r.MetadataKeyId);
		FfiDestroyerOptionalString{}.Destroy(r.MetadataKeyType);
}

type FfiConverterFfiResource struct {}

var FfiConverterFfiResourceINSTANCE = FfiConverterFfiResource{}

func (c FfiConverterFfiResource) Lift(rb RustBufferI) FfiResource {
	return LiftFromRustBuffer[FfiResource](c, rb)
}

func (c FfiConverterFfiResource) Read(reader io.Reader) FfiResource {
	return FfiResource {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalFfiFavoriteINSTANCE.Read(reader),
			FfiConverterSequenceFfiSecretINSTANCE.Read(reader),
			FfiConverterSequenceFfiPermissionINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiResource) Lower(value FfiResource) C.RustBuffer {
	return LowerIntoRustBuffer[FfiResource](c, value)
}

func (c FfiConverterFfiResource) LowerExternal(value FfiResource) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiResource](c, value))
}

func (c FfiConverterFfiResource) Write(writer io.Writer, value FfiResource) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Name);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Username);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Uri);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Description);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.FolderParentId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ResourceTypeId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.CreatedBy);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ModifiedBy);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.Personal);
		FfiConverterOptionalFfiFavoriteINSTANCE.Write(writer, value.Favorite);
		FfiConverterSequenceFfiSecretINSTANCE.Write(writer, value.Secrets);
		FfiConverterSequenceFfiPermissionINSTANCE.Write(writer, value.Permissions);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Expired);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Metadata);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.MetadataKeyType);
}

type FfiDestroyerFfiResource struct {}

func (_ FfiDestroyerFfiResource) Destroy(value FfiResource) {
	value.Destroy()
}

type FfiResourceQuery struct {
	Search *string
	FavoritesOnly bool
	OwnedByMe bool
}

func (r *FfiResourceQuery) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Search);
		FfiDestroyerBool{}.Destroy(r.FavoritesOnly);
		FfiDestroyerBool{}.Destroy(r.OwnedByMe);
}

type FfiConverterFfiResourceQuery struct {}

var FfiConverterFfiResourceQueryINSTANCE = FfiConverterFfiResourceQuery{}

func (c FfiConverterFfiResourceQuery) Lift(rb RustBufferI) FfiResourceQuery {
	return LiftFromRustBuffer[FfiResourceQuery](c, rb)
}

func (c FfiConverterFfiResourceQuery) Read(reader io.Reader) FfiResourceQuery {
	return FfiResourceQuery {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterBoolINSTANCE.Read(reader),
			FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiResourceQuery) Lower(value FfiResourceQuery) C.RustBuffer {
	return LowerIntoRustBuffer[FfiResourceQuery](c, value)
}

func (c FfiConverterFfiResourceQuery) LowerExternal(value FfiResourceQuery) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiResourceQuery](c, value))
}

func (c FfiConverterFfiResourceQuery) Write(writer io.Writer, value FfiResourceQuery) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Search);
		FfiConverterBoolINSTANCE.Write(writer, value.FavoritesOnly);
		FfiConverterBoolINSTANCE.Write(writer, value.OwnedByMe);
}

type FfiDestroyerFfiResourceQuery struct {}

func (_ FfiDestroyerFfiResourceQuery) Destroy(value FfiResourceQuery) {
	value.Destroy()
}

// A resource type of the server; `definition` is its JSON Schema, as JSON.
type FfiResourceType struct {
	Id string
	Slug string
	Name *string
	Definition *string
}

func (r *FfiResourceType) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Slug);
		FfiDestroyerOptionalString{}.Destroy(r.Name);
		FfiDestroyerOptionalString{}.Destroy(r.Definition);
}

type FfiConverterFfiResourceType struct {}

var FfiConverterFfiResourceTypeINSTANCE = FfiConverterFfiResourceType{}

func (c FfiConverterFfiResourceType) Lift(rb RustBufferI) FfiResourceType {
	return LiftFromRustBuffer[FfiResourceType](c, rb)
}

func (c FfiConverterFfiResourceType) Read(reader io.Reader) FfiResourceType {
	return FfiResourceType {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiResourceType) Lower(value FfiResourceType) C.RustBuffer {
	return LowerIntoRustBuffer[FfiResourceType](c, value)
}

func (c FfiConverterFfiResourceType) LowerExternal(value FfiResourceType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiResourceType](c, value))
}

func (c FfiConverterFfiResourceType) Write(writer io.Writer, value FfiResourceType) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Slug);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Name);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Definition);
}

type FfiDestroyerFfiResourceType struct {}

func (_ FfiDestroyerFfiResourceType) Destroy(value FfiResourceType) {
	value.Destroy()
}

type FfiRole struct {
	Id *string
	Name *string
}

func (r *FfiRole) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.Name);
}

type FfiConverterFfiRole struct {}

var FfiConverterFfiRoleINSTANCE = FfiConverterFfiRole{}

func (c FfiConverterFfiRole) Lift(rb RustBufferI) FfiRole {
	return LiftFromRustBuffer[FfiRole](c, rb)
}

func (c FfiConverterFfiRole) Read(reader io.Reader) FfiRole {
	return FfiRole {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiRole) Lower(value FfiRole) C.RustBuffer {
	return LowerIntoRustBuffer[FfiRole](c, value)
}

func (c FfiConverterFfiRole) LowerExternal(value FfiRole) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiRole](c, value))
}

func (c FfiConverterFfiRole) Write(writer io.Writer, value FfiRole) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Name);
}

type FfiDestroyerFfiRole struct {}

func (_ FfiDestroyerFfiRole) Destroy(value FfiRole) {
	value.Destroy()
}

type FfiSecret struct {
	Id *string
	ResourceId *string
	UserId *string
	Data *string
	Created *string
	Modified *string
}

func (r *FfiSecret) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.ResourceId);
		FfiDestroyerOptionalString{}.Destroy(r.UserId);
		FfiDestroyerOptionalString{}.Destroy(r.Data);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
}

type FfiConverterFfiSecret struct {}

var FfiConverterFfiSecretINSTANCE = FfiConverterFfiSecret{}

func (c FfiConverterFfiSecret) Lift(rb RustBufferI) FfiSecret {
	return LiftFromRustBuffer[FfiSecret](c, rb)
}

func (c FfiConverterFfiSecret) Read(reader io.Reader) FfiSecret {
	return FfiSecret {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiSecret) Lower(value FfiSecret) C.RustBuffer {
	return LowerIntoRustBuffer[FfiSecret](c, value)
}

func (c FfiConverterFfiSecret) LowerExternal(value FfiSecret) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiSecret](c, value))
}

func (c FfiConverterFfiSecret) Write(writer io.Writer, value FfiSecret) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.ResourceId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.UserId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Data);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
}

type FfiDestroyerFfiSecret struct {}

func (_ FfiDestroyerFfiSecret) Destroy(value FfiSecret) {
	value.Destroy()
}

type FfiSecretData struct {
	Password *string
	Description *string
	Totp *FfiTotpData
	Raw *string
}

func (r *FfiSecretData) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Password);
		FfiDestroyerOptionalString{}.Destroy(r.Description);
		FfiDestroyerOptionalFfiTotpData{}.Destroy(r.Totp);
		FfiDestroyerOptionalString{}.Destroy(r.Raw);
}

type FfiConverterFfiSecretData struct {}

var FfiConverterFfiSecretDataINSTANCE = FfiConverterFfiSecretData{}

func (c FfiConverterFfiSecretData) Lift(rb RustBufferI) FfiSecretData {
	return LiftFromRustBuffer[FfiSecretData](c, rb)
}

func (c FfiConverterFfiSecretData) Read(reader io.Reader) FfiSecretData {
	return FfiSecretData {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalFfiTotpDataINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiSecretData) Lower(value FfiSecretData) C.RustBuffer {
	return LowerIntoRustBuffer[FfiSecretData](c, value)
}

func (c FfiConverterFfiSecretData) LowerExternal(value FfiSecretData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiSecretData](c, value))
}

func (c FfiConverterFfiSecretData) Write(writer io.Writer, value FfiSecretData) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Password);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Description);
		FfiConverterOptionalFfiTotpDataINSTANCE.Write(writer, value.Totp);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Raw);
}

type FfiDestroyerFfiSecretData struct {}

func (_ FfiDestroyerFfiSecretData) Destroy(value FfiSecretData) {
	value.Destroy()
}

// The server public key, to pin.
type FfiServerKey struct {
	// Computed from the key, checked against the one the server announces.
	Fingerprint string
	ArmoredKey string
}

func (r *FfiServerKey) Destroy() {
		FfiDestroyerString{}.Destroy(r.Fingerprint);
		FfiDestroyerString{}.Destroy(r.ArmoredKey);
}

type FfiConverterFfiServerKey struct {}

var FfiConverterFfiServerKeyINSTANCE = FfiConverterFfiServerKey{}

func (c FfiConverterFfiServerKey) Lift(rb RustBufferI) FfiServerKey {
	return LiftFromRustBuffer[FfiServerKey](c, rb)
}

func (c FfiConverterFfiServerKey) Read(reader io.Reader) FfiServerKey {
	return FfiServerKey {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiServerKey) Lower(value FfiServerKey) C.RustBuffer {
	return LowerIntoRustBuffer[FfiServerKey](c, value)
}

func (c FfiConverterFfiServerKey) LowerExternal(value FfiServerKey) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiServerKey](c, value))
}

func (c FfiConverterFfiServerKey) Write(writer io.Writer, value FfiServerKey) {
		FfiConverterStringINSTANCE.Write(writer, value.Fingerprint);
		FfiConverterStringINSTANCE.Write(writer, value.ArmoredKey);
}

type FfiDestroyerFfiServerKey struct {}

func (_ FfiDestroyerFfiServerKey) Destroy(value FfiServerKey) {
	value.Destroy()
}

type FfiTag struct {
	Id string
	Slug string
	IsShared *bool
	Created *string
	Modified *string
}

func (r *FfiTag) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerString{}.Destroy(r.Slug);
		FfiDestroyerOptionalBool{}.Destroy(r.IsShared);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
}

type FfiConverterFfiTag struct {}

var FfiConverterFfiTagINSTANCE = FfiConverterFfiTag{}

func (c FfiConverterFfiTag) Lift(rb RustBufferI) FfiTag {
	return LiftFromRustBuffer[FfiTag](c, rb)
}

func (c FfiConverterFfiTag) Read(reader io.Reader) FfiTag {
	return FfiTag {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiTag) Lower(value FfiTag) C.RustBuffer {
	return LowerIntoRustBuffer[FfiTag](c, value)
}

func (c FfiConverterFfiTag) LowerExternal(value FfiTag) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiTag](c, value))
}

func (c FfiConverterFfiTag) Write(writer io.Writer, value FfiTag) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterStringINSTANCE.Write(writer, value.Slug);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.IsShared);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
}

type FfiDestroyerFfiTag struct {}

func (_ FfiDestroyerFfiTag) Destroy(value FfiTag) {
	value.Destroy()
}

type FfiTotpData struct {
	SecretKey *string
	Algorithm *string
	Digits *uint32
	Period *uint64
	Issuer *string
}

func (r *FfiTotpData) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.SecretKey);
		FfiDestroyerOptionalString{}.Destroy(r.Algorithm);
		FfiDestroyerOptionalUint32{}.Destroy(r.Digits);
		FfiDestroyerOptionalUint64{}.Destroy(r.Period);
		FfiDestroyerOptionalString{}.Destroy(r.Issuer);
}

type FfiConverterFfiTotpData struct {}

var FfiConverterFfiTotpDataINSTANCE = FfiConverterFfiTotpData{}

func (c FfiConverterFfiTotpData) Lift(rb RustBufferI) FfiTotpData {
	return LiftFromRustBuffer[FfiTotpData](c, rb)
}

func (c FfiConverterFfiTotpData) Read(reader io.Reader) FfiTotpData {
	return FfiTotpData {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalUint32INSTANCE.Read(reader),
			FfiConverterOptionalUint64INSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiTotpData) Lower(value FfiTotpData) C.RustBuffer {
	return LowerIntoRustBuffer[FfiTotpData](c, value)
}

func (c FfiConverterFfiTotpData) LowerExternal(value FfiTotpData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiTotpData](c, value))
}

func (c FfiConverterFfiTotpData) Write(writer io.Writer, value FfiTotpData) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.SecretKey);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Algorithm);
		FfiConverterOptionalUint32INSTANCE.Write(writer, value.Digits);
		FfiConverterOptionalUint64INSTANCE.Write(writer, value.Period);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Issuer);
}

type FfiDestroyerFfiTotpData struct {}

func (_ FfiDestroyerFfiTotpData) Destroy(value FfiTotpData) {
	value.Destroy()
}

type FfiUser struct {
	Id string
	Username *string
	RoleId *string
	Created *string
	Modified *string
	Active *bool
	Deleted *bool
	Profile *FfiUserProfile
	Role *FfiRole
	GpgKey *FfiGpgKey
}

func (r *FfiUser) Destroy() {
		FfiDestroyerString{}.Destroy(r.Id);
		FfiDestroyerOptionalString{}.Destroy(r.Username);
		FfiDestroyerOptionalString{}.Destroy(r.RoleId);
		FfiDestroyerOptionalString{}.Destroy(r.Created);
		FfiDestroyerOptionalString{}.Destroy(r.Modified);
		FfiDestroyerOptionalBool{}.Destroy(r.Active);
		FfiDestroyerOptionalBool{}.Destroy(r.Deleted);
		FfiDestroyerOptionalFfiUserProfile{}.Destroy(r.Profile);
		FfiDestroyerOptionalFfiRole{}.Destroy(r.Role);
		FfiDestroyerOptionalFfiGpgKey{}.Destroy(r.GpgKey);
}

type FfiConverterFfiUser struct {}

var FfiConverterFfiUserINSTANCE = FfiConverterFfiUser{}

func (c FfiConverterFfiUser) Lift(rb RustBufferI) FfiUser {
	return LiftFromRustBuffer[FfiUser](c, rb)
}

func (c FfiConverterFfiUser) Read(reader io.Reader) FfiUser {
	return FfiUser {
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalBoolINSTANCE.Read(reader),
			FfiConverterOptionalFfiUserProfileINSTANCE.Read(reader),
			FfiConverterOptionalFfiRoleINSTANCE.Read(reader),
			FfiConverterOptionalFfiGpgKeyINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiUser) Lower(value FfiUser) C.RustBuffer {
	return LowerIntoRustBuffer[FfiUser](c, value)
}

func (c FfiConverterFfiUser) LowerExternal(value FfiUser) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiUser](c, value))
}

func (c FfiConverterFfiUser) Write(writer io.Writer, value FfiUser) {
		FfiConverterStringINSTANCE.Write(writer, value.Id);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Username);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.RoleId);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Created);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Modified);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.Active);
		FfiConverterOptionalBoolINSTANCE.Write(writer, value.Deleted);
		FfiConverterOptionalFfiUserProfileINSTANCE.Write(writer, value.Profile);
		FfiConverterOptionalFfiRoleINSTANCE.Write(writer, value.Role);
		FfiConverterOptionalFfiGpgKeyINSTANCE.Write(writer, value.GpgKey);
}

type FfiDestroyerFfiUser struct {}

func (_ FfiDestroyerFfiUser) Destroy(value FfiUser) {
	value.Destroy()
}

type FfiUserDeleteDryRun struct {
	ResourcesSoleOwnerCount uint32
	FoldersSoleOwnerCount uint32
	GroupsSoleManagerCount uint32
}

func (r *FfiUserDeleteDryRun) Destroy() {
		FfiDestroyerUint32{}.Destroy(r.ResourcesSoleOwnerCount);
		FfiDestroyerUint32{}.Destroy(r.FoldersSoleOwnerCount);
		FfiDestroyerUint32{}.Destroy(r.GroupsSoleManagerCount);
}

type FfiConverterFfiUserDeleteDryRun struct {}

var FfiConverterFfiUserDeleteDryRunINSTANCE = FfiConverterFfiUserDeleteDryRun{}

func (c FfiConverterFfiUserDeleteDryRun) Lift(rb RustBufferI) FfiUserDeleteDryRun {
	return LiftFromRustBuffer[FfiUserDeleteDryRun](c, rb)
}

func (c FfiConverterFfiUserDeleteDryRun) Read(reader io.Reader) FfiUserDeleteDryRun {
	return FfiUserDeleteDryRun {
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiUserDeleteDryRun) Lower(value FfiUserDeleteDryRun) C.RustBuffer {
	return LowerIntoRustBuffer[FfiUserDeleteDryRun](c, value)
}

func (c FfiConverterFfiUserDeleteDryRun) LowerExternal(value FfiUserDeleteDryRun) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiUserDeleteDryRun](c, value))
}

func (c FfiConverterFfiUserDeleteDryRun) Write(writer io.Writer, value FfiUserDeleteDryRun) {
		FfiConverterUint32INSTANCE.Write(writer, value.ResourcesSoleOwnerCount);
		FfiConverterUint32INSTANCE.Write(writer, value.FoldersSoleOwnerCount);
		FfiConverterUint32INSTANCE.Write(writer, value.GroupsSoleManagerCount);
}

type FfiDestroyerFfiUserDeleteDryRun struct {}

func (_ FfiDestroyerFfiUserDeleteDryRun) Destroy(value FfiUserDeleteDryRun) {
	value.Destroy()
}

type FfiUserProfile struct {
	FirstName *string
	LastName *string
}

func (r *FfiUserProfile) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.FirstName);
		FfiDestroyerOptionalString{}.Destroy(r.LastName);
}

type FfiConverterFfiUserProfile struct {}

var FfiConverterFfiUserProfileINSTANCE = FfiConverterFfiUserProfile{}

func (c FfiConverterFfiUserProfile) Lift(rb RustBufferI) FfiUserProfile {
	return LiftFromRustBuffer[FfiUserProfile](c, rb)
}

func (c FfiConverterFfiUserProfile) Read(reader io.Reader) FfiUserProfile {
	return FfiUserProfile {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiUserProfile) Lower(value FfiUserProfile) C.RustBuffer {
	return LowerIntoRustBuffer[FfiUserProfile](c, value)
}

func (c FfiConverterFfiUserProfile) LowerExternal(value FfiUserProfile) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiUserProfile](c, value))
}

func (c FfiConverterFfiUserProfile) Write(writer io.Writer, value FfiUserProfile) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.FirstName);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.LastName);
}

type FfiDestroyerFfiUserProfile struct {}

func (_ FfiDestroyerFfiUserProfile) Destroy(value FfiUserProfile) {
	value.Destroy()
}

type FfiUserQuery struct {
	Search *string
	GroupId *string
	AdminOnly bool
}

func (r *FfiUserQuery) Destroy() {
		FfiDestroyerOptionalString{}.Destroy(r.Search);
		FfiDestroyerOptionalString{}.Destroy(r.GroupId);
		FfiDestroyerBool{}.Destroy(r.AdminOnly);
}

type FfiConverterFfiUserQuery struct {}

var FfiConverterFfiUserQueryINSTANCE = FfiConverterFfiUserQuery{}

func (c FfiConverterFfiUserQuery) Lift(rb RustBufferI) FfiUserQuery {
	return LiftFromRustBuffer[FfiUserQuery](c, rb)
}

func (c FfiConverterFfiUserQuery) Read(reader io.Reader) FfiUserQuery {
	return FfiUserQuery {
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterOptionalStringINSTANCE.Read(reader),
			FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterFfiUserQuery) Lower(value FfiUserQuery) C.RustBuffer {
	return LowerIntoRustBuffer[FfiUserQuery](c, value)
}

func (c FfiConverterFfiUserQuery) LowerExternal(value FfiUserQuery) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[FfiUserQuery](c, value))
}

func (c FfiConverterFfiUserQuery) Write(writer io.Writer, value FfiUserQuery) {
		FfiConverterOptionalStringINSTANCE.Write(writer, value.Search);
		FfiConverterOptionalStringINSTANCE.Write(writer, value.GroupId);
		FfiConverterBoolINSTANCE.Write(writer, value.AdminOnly);
}

type FfiDestroyerFfiUserQuery struct {}

func (_ FfiDestroyerFfiUserQuery) Destroy(value FfiUserQuery) {
	value.Destroy()
}
// FFI-safe error type exposed to all target languages.
type PassboltFfiError struct {
	err error
}

// Convience method to turn *PassboltFfiError into error
// Avoiding treating nil pointer as non nil error interface
func (err *PassboltFfiError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err PassboltFfiError) Error() string {
	return fmt.Sprintf("PassboltFfiError: %s", err.err.Error())
}

func (err PassboltFfiError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrPassboltFfiErrorTransport = fmt.Errorf("PassboltFfiErrorTransport")
var ErrPassboltFfiErrorAuth = fmt.Errorf("PassboltFfiErrorAuth")
var ErrPassboltFfiErrorCrypto = fmt.Errorf("PassboltFfiErrorCrypto")
var ErrPassboltFfiErrorApi = fmt.Errorf("PassboltFfiErrorApi")
var ErrPassboltFfiErrorNotFound = fmt.Errorf("PassboltFfiErrorNotFound")
var ErrPassboltFfiErrorConfig = fmt.Errorf("PassboltFfiErrorConfig")
var ErrPassboltFfiErrorInvalidArgument = fmt.Errorf("PassboltFfiErrorInvalidArgument")
var ErrPassboltFfiErrorOther = fmt.Errorf("PassboltFfiErrorOther")

// Variant structs
type PassboltFfiErrorTransport struct {
	Reason string
}
func NewPassboltFfiErrorTransport(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorTransport {
			Reason: reason,} }
}

func (e PassboltFfiErrorTransport) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorTransport) Error() string {
	return fmt.Sprint("Transport",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorTransport) Is(target error) bool {
	return target == ErrPassboltFfiErrorTransport
}
type PassboltFfiErrorAuth struct {
	Reason string
}
func NewPassboltFfiErrorAuth(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorAuth {
			Reason: reason,} }
}

func (e PassboltFfiErrorAuth) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorAuth) Error() string {
	return fmt.Sprint("Auth",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorAuth) Is(target error) bool {
	return target == ErrPassboltFfiErrorAuth
}
type PassboltFfiErrorCrypto struct {
	Reason string
}
func NewPassboltFfiErrorCrypto(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorCrypto {
			Reason: reason,} }
}

func (e PassboltFfiErrorCrypto) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorCrypto) Error() string {
	return fmt.Sprint("Crypto",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorCrypto) Is(target error) bool {
	return target == ErrPassboltFfiErrorCrypto
}
type PassboltFfiErrorApi struct {
	Status uint16
	Reason string
}
func NewPassboltFfiErrorApi(
	status uint16,
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorApi {
			Status: status,
			Reason: reason,} }
}

func (e PassboltFfiErrorApi) destroy() {
		FfiDestroyerUint16{}.Destroy(e.Status)
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorApi) Error() string {
	return fmt.Sprint("Api",
		": ",
		
		"Status=",
		err.Status,
		", ",
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorApi) Is(target error) bool {
	return target == ErrPassboltFfiErrorApi
}
type PassboltFfiErrorNotFound struct {
	Reason string
}
func NewPassboltFfiErrorNotFound(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorNotFound {
			Reason: reason,} }
}

func (e PassboltFfiErrorNotFound) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorNotFound) Error() string {
	return fmt.Sprint("NotFound",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorNotFound) Is(target error) bool {
	return target == ErrPassboltFfiErrorNotFound
}
type PassboltFfiErrorConfig struct {
	Reason string
}
func NewPassboltFfiErrorConfig(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorConfig {
			Reason: reason,} }
}

func (e PassboltFfiErrorConfig) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorConfig) Error() string {
	return fmt.Sprint("Config",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorConfig) Is(target error) bool {
	return target == ErrPassboltFfiErrorConfig
}
type PassboltFfiErrorInvalidArgument struct {
	Reason string
}
func NewPassboltFfiErrorInvalidArgument(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorInvalidArgument {
			Reason: reason,} }
}

func (e PassboltFfiErrorInvalidArgument) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorInvalidArgument) Error() string {
	return fmt.Sprint("InvalidArgument",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorInvalidArgument) Is(target error) bool {
	return target == ErrPassboltFfiErrorInvalidArgument
}
type PassboltFfiErrorOther struct {
	Reason string
}
func NewPassboltFfiErrorOther(
	reason string,
) *PassboltFfiError {
	return &PassboltFfiError { err: &PassboltFfiErrorOther {
			Reason: reason,} }
}

func (e PassboltFfiErrorOther) destroy() {
		FfiDestroyerString{}.Destroy(e.Reason)
}


func (err PassboltFfiErrorOther) Error() string {
	return fmt.Sprint("Other",
		": ",
		
		"Reason=",
		err.Reason,
	)
}

func (self PassboltFfiErrorOther) Is(target error) bool {
	return target == ErrPassboltFfiErrorOther
}

type FfiConverterPassboltFfiError struct{}

var FfiConverterPassboltFfiErrorINSTANCE = FfiConverterPassboltFfiError{}

func (c FfiConverterPassboltFfiError) Lift(eb RustBufferI) *PassboltFfiError {
	return LiftFromRustBuffer[*PassboltFfiError](c, eb)
}

func (c FfiConverterPassboltFfiError) Lower(value *PassboltFfiError) C.RustBuffer {
	return LowerIntoRustBuffer[*PassboltFfiError](c, value)
}

func (c FfiConverterPassboltFfiError) LowerExternal(value *PassboltFfiError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*PassboltFfiError](c, value))
}

func (c FfiConverterPassboltFfiError) Read(reader io.Reader) *PassboltFfiError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &PassboltFfiError{ &PassboltFfiErrorTransport{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 2:
		return &PassboltFfiError{ &PassboltFfiErrorAuth{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 3:
		return &PassboltFfiError{ &PassboltFfiErrorCrypto{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 4:
		return &PassboltFfiError{ &PassboltFfiErrorApi{
			Status: FfiConverterUint16INSTANCE.Read(reader),
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 5:
		return &PassboltFfiError{ &PassboltFfiErrorNotFound{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 6:
		return &PassboltFfiError{ &PassboltFfiErrorConfig{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 7:
		return &PassboltFfiError{ &PassboltFfiErrorInvalidArgument{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 8:
		return &PassboltFfiError{ &PassboltFfiErrorOther{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterPassboltFfiError.Read()", errorID))
	}
}

func (c FfiConverterPassboltFfiError) Write(writer io.Writer, value *PassboltFfiError) {
	switch variantValue := value.err.(type) {
		case *PassboltFfiErrorTransport:
			writeInt32(writer, 1)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorAuth:
			writeInt32(writer, 2)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorCrypto:
			writeInt32(writer, 3)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorApi:
			writeInt32(writer, 4)
			FfiConverterUint16INSTANCE.Write(writer, variantValue.Status)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorNotFound:
			writeInt32(writer, 5)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorConfig:
			writeInt32(writer, 6)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorInvalidArgument:
			writeInt32(writer, 7)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		case *PassboltFfiErrorOther:
			writeInt32(writer, 8)
			FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiConverterPassboltFfiError.Write", value))
	}
}

type FfiDestroyerPassboltFfiError struct {}

func (_ FfiDestroyerPassboltFfiError) Destroy(value *PassboltFfiError) {
	switch variantValue := value.err.(type) {
		case PassboltFfiErrorTransport:
			variantValue.destroy()
		case PassboltFfiErrorAuth:
			variantValue.destroy()
		case PassboltFfiErrorCrypto:
			variantValue.destroy()
		case PassboltFfiErrorApi:
			variantValue.destroy()
		case PassboltFfiErrorNotFound:
			variantValue.destroy()
		case PassboltFfiErrorConfig:
			variantValue.destroy()
		case PassboltFfiErrorInvalidArgument:
			variantValue.destroy()
		case PassboltFfiErrorOther:
			variantValue.destroy()
		default:
			_ = variantValue
			panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerPassboltFfiError.Destroy", value))
	}
}



type FfiConverterOptionalUint32 struct{}

var FfiConverterOptionalUint32INSTANCE = FfiConverterOptionalUint32{}

func (c FfiConverterOptionalUint32) Lift(rb RustBufferI) *uint32 {
	return LiftFromRustBuffer[*uint32](c, rb)
}

func (_ FfiConverterOptionalUint32) Read(reader io.Reader) *uint32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint32) Lower(value *uint32) C.RustBuffer {
	return LowerIntoRustBuffer[*uint32](c, value)
}

func (c FfiConverterOptionalUint32) LowerExternal(value *uint32) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*uint32](c, value))
}

func (_ FfiConverterOptionalUint32) Write(writer io.Writer, value *uint32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint32 struct {}

func (_ FfiDestroyerOptionalUint32) Destroy(value *uint32) {
	if value != nil {
		FfiDestroyerUint32{}.Destroy(*value)
	}
}


type FfiConverterOptionalInt32 struct{}

var FfiConverterOptionalInt32INSTANCE = FfiConverterOptionalInt32{}

func (c FfiConverterOptionalInt32) Lift(rb RustBufferI) *int32 {
	return LiftFromRustBuffer[*int32](c, rb)
}

func (_ FfiConverterOptionalInt32) Read(reader io.Reader) *int32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterInt32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalInt32) Lower(value *int32) C.RustBuffer {
	return LowerIntoRustBuffer[*int32](c, value)
}

func (c FfiConverterOptionalInt32) LowerExternal(value *int32) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*int32](c, value))
}

func (_ FfiConverterOptionalInt32) Write(writer io.Writer, value *int32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterInt32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalInt32 struct {}

func (_ FfiDestroyerOptionalInt32) Destroy(value *int32) {
	if value != nil {
		FfiDestroyerInt32{}.Destroy(*value)
	}
}


type FfiConverterOptionalUint64 struct{}

var FfiConverterOptionalUint64INSTANCE = FfiConverterOptionalUint64{}

func (c FfiConverterOptionalUint64) Lift(rb RustBufferI) *uint64 {
	return LiftFromRustBuffer[*uint64](c, rb)
}

func (_ FfiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint64) Lower(value *uint64) C.RustBuffer {
	return LowerIntoRustBuffer[*uint64](c, value)
}

func (c FfiConverterOptionalUint64) LowerExternal(value *uint64) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*uint64](c, value))
}

func (_ FfiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint64 struct {}

func (_ FfiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		FfiDestroyerUint64{}.Destroy(*value)
	}
}


type FfiConverterOptionalBool struct{}

var FfiConverterOptionalBoolINSTANCE = FfiConverterOptionalBool{}

func (c FfiConverterOptionalBool) Lift(rb RustBufferI) *bool {
	return LiftFromRustBuffer[*bool](c, rb)
}

func (_ FfiConverterOptionalBool) Read(reader io.Reader) *bool {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBoolINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBool) Lower(value *bool) C.RustBuffer {
	return LowerIntoRustBuffer[*bool](c, value)
}

func (c FfiConverterOptionalBool) LowerExternal(value *bool) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*bool](c, value))
}

func (_ FfiConverterOptionalBool) Write(writer io.Writer, value *bool) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBoolINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBool struct {}

func (_ FfiDestroyerOptionalBool) Destroy(value *bool) {
	if value != nil {
		FfiDestroyerBool{}.Destroy(*value)
	}
}


type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (c FfiConverterOptionalString) LowerExternal(value *string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*string](c, value))
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct {}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiFavorite struct{}

var FfiConverterOptionalFfiFavoriteINSTANCE = FfiConverterOptionalFfiFavorite{}

func (c FfiConverterOptionalFfiFavorite) Lift(rb RustBufferI) *FfiFavorite {
	return LiftFromRustBuffer[*FfiFavorite](c, rb)
}

func (_ FfiConverterOptionalFfiFavorite) Read(reader io.Reader) *FfiFavorite {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiFavoriteINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiFavorite) Lower(value *FfiFavorite) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiFavorite](c, value)
}

func (c FfiConverterOptionalFfiFavorite) LowerExternal(value *FfiFavorite) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiFavorite](c, value))
}

func (_ FfiConverterOptionalFfiFavorite) Write(writer io.Writer, value *FfiFavorite) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiFavoriteINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiFavorite struct {}

func (_ FfiDestroyerOptionalFfiFavorite) Destroy(value *FfiFavorite) {
	if value != nil {
		FfiDestroyerFfiFavorite{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiGpgKey struct{}

var FfiConverterOptionalFfiGpgKeyINSTANCE = FfiConverterOptionalFfiGpgKey{}

func (c FfiConverterOptionalFfiGpgKey) Lift(rb RustBufferI) *FfiGpgKey {
	return LiftFromRustBuffer[*FfiGpgKey](c, rb)
}

func (_ FfiConverterOptionalFfiGpgKey) Read(reader io.Reader) *FfiGpgKey {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiGpgKeyINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiGpgKey) Lower(value *FfiGpgKey) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiGpgKey](c, value)
}

func (c FfiConverterOptionalFfiGpgKey) LowerExternal(value *FfiGpgKey) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiGpgKey](c, value))
}

func (_ FfiConverterOptionalFfiGpgKey) Write(writer io.Writer, value *FfiGpgKey) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiGpgKeyINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiGpgKey struct {}

func (_ FfiDestroyerOptionalFfiGpgKey) Destroy(value *FfiGpgKey) {
	if value != nil {
		FfiDestroyerFfiGpgKey{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiGroup struct{}

var FfiConverterOptionalFfiGroupINSTANCE = FfiConverterOptionalFfiGroup{}

func (c FfiConverterOptionalFfiGroup) Lift(rb RustBufferI) *FfiGroup {
	return LiftFromRustBuffer[*FfiGroup](c, rb)
}

func (_ FfiConverterOptionalFfiGroup) Read(reader io.Reader) *FfiGroup {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiGroupINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiGroup) Lower(value *FfiGroup) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiGroup](c, value)
}

func (c FfiConverterOptionalFfiGroup) LowerExternal(value *FfiGroup) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiGroup](c, value))
}

func (_ FfiConverterOptionalFfiGroup) Write(writer io.Writer, value *FfiGroup) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiGroupINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiGroup struct {}

func (_ FfiDestroyerOptionalFfiGroup) Destroy(value *FfiGroup) {
	if value != nil {
		FfiDestroyerFfiGroup{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiRole struct{}

var FfiConverterOptionalFfiRoleINSTANCE = FfiConverterOptionalFfiRole{}

func (c FfiConverterOptionalFfiRole) Lift(rb RustBufferI) *FfiRole {
	return LiftFromRustBuffer[*FfiRole](c, rb)
}

func (_ FfiConverterOptionalFfiRole) Read(reader io.Reader) *FfiRole {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiRoleINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiRole) Lower(value *FfiRole) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiRole](c, value)
}

func (c FfiConverterOptionalFfiRole) LowerExternal(value *FfiRole) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiRole](c, value))
}

func (_ FfiConverterOptionalFfiRole) Write(writer io.Writer, value *FfiRole) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiRoleINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiRole struct {}

func (_ FfiDestroyerOptionalFfiRole) Destroy(value *FfiRole) {
	if value != nil {
		FfiDestroyerFfiRole{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiTotpData struct{}

var FfiConverterOptionalFfiTotpDataINSTANCE = FfiConverterOptionalFfiTotpData{}

func (c FfiConverterOptionalFfiTotpData) Lift(rb RustBufferI) *FfiTotpData {
	return LiftFromRustBuffer[*FfiTotpData](c, rb)
}

func (_ FfiConverterOptionalFfiTotpData) Read(reader io.Reader) *FfiTotpData {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiTotpDataINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiTotpData) Lower(value *FfiTotpData) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiTotpData](c, value)
}

func (c FfiConverterOptionalFfiTotpData) LowerExternal(value *FfiTotpData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiTotpData](c, value))
}

func (_ FfiConverterOptionalFfiTotpData) Write(writer io.Writer, value *FfiTotpData) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiTotpDataINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiTotpData struct {}

func (_ FfiDestroyerOptionalFfiTotpData) Destroy(value *FfiTotpData) {
	if value != nil {
		FfiDestroyerFfiTotpData{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiUser struct{}

var FfiConverterOptionalFfiUserINSTANCE = FfiConverterOptionalFfiUser{}

func (c FfiConverterOptionalFfiUser) Lift(rb RustBufferI) *FfiUser {
	return LiftFromRustBuffer[*FfiUser](c, rb)
}

func (_ FfiConverterOptionalFfiUser) Read(reader io.Reader) *FfiUser {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiUserINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiUser) Lower(value *FfiUser) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiUser](c, value)
}

func (c FfiConverterOptionalFfiUser) LowerExternal(value *FfiUser) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiUser](c, value))
}

func (_ FfiConverterOptionalFfiUser) Write(writer io.Writer, value *FfiUser) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiUserINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiUser struct {}

func (_ FfiDestroyerOptionalFfiUser) Destroy(value *FfiUser) {
	if value != nil {
		FfiDestroyerFfiUser{}.Destroy(*value)
	}
}


type FfiConverterOptionalFfiUserProfile struct{}

var FfiConverterOptionalFfiUserProfileINSTANCE = FfiConverterOptionalFfiUserProfile{}

func (c FfiConverterOptionalFfiUserProfile) Lift(rb RustBufferI) *FfiUserProfile {
	return LiftFromRustBuffer[*FfiUserProfile](c, rb)
}

func (_ FfiConverterOptionalFfiUserProfile) Read(reader io.Reader) *FfiUserProfile {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterFfiUserProfileINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalFfiUserProfile) Lower(value *FfiUserProfile) C.RustBuffer {
	return LowerIntoRustBuffer[*FfiUserProfile](c, value)
}

func (c FfiConverterOptionalFfiUserProfile) LowerExternal(value *FfiUserProfile) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*FfiUserProfile](c, value))
}

func (_ FfiConverterOptionalFfiUserProfile) Write(writer io.Writer, value *FfiUserProfile) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterFfiUserProfileINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalFfiUserProfile struct {}

func (_ FfiDestroyerOptionalFfiUserProfile) Destroy(value *FfiUserProfile) {
	if value != nil {
		FfiDestroyerFfiUserProfile{}.Destroy(*value)
	}
}


type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) LowerExternal(value []string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]string](c, value))
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct {}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiAro struct{}

var FfiConverterSequenceFfiAroINSTANCE = FfiConverterSequenceFfiAro{}

func (c FfiConverterSequenceFfiAro) Lift(rb RustBufferI) []FfiAro {
	return LiftFromRustBuffer[[]FfiAro](c, rb)
}

func (c FfiConverterSequenceFfiAro) Read(reader io.Reader) []FfiAro {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiAro, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiAroINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiAro) Lower(value []FfiAro) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiAro](c, value)
}

func (c FfiConverterSequenceFfiAro) LowerExternal(value []FfiAro) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiAro](c, value))
}

func (c FfiConverterSequenceFfiAro) Write(writer io.Writer, value []FfiAro) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiAro is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiAroINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiAro struct {}

func (FfiDestroyerSequenceFfiAro) Destroy(sequence []FfiAro) {
	for _, value := range sequence {
		FfiDestroyerFfiAro{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiComment struct{}

var FfiConverterSequenceFfiCommentINSTANCE = FfiConverterSequenceFfiComment{}

func (c FfiConverterSequenceFfiComment) Lift(rb RustBufferI) []FfiComment {
	return LiftFromRustBuffer[[]FfiComment](c, rb)
}

func (c FfiConverterSequenceFfiComment) Read(reader io.Reader) []FfiComment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiComment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiCommentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiComment) Lower(value []FfiComment) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiComment](c, value)
}

func (c FfiConverterSequenceFfiComment) LowerExternal(value []FfiComment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiComment](c, value))
}

func (c FfiConverterSequenceFfiComment) Write(writer io.Writer, value []FfiComment) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiComment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiCommentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiComment struct {}

func (FfiDestroyerSequenceFfiComment) Destroy(sequence []FfiComment) {
	for _, value := range sequence {
		FfiDestroyerFfiComment{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiFolder struct{}

var FfiConverterSequenceFfiFolderINSTANCE = FfiConverterSequenceFfiFolder{}

func (c FfiConverterSequenceFfiFolder) Lift(rb RustBufferI) []FfiFolder {
	return LiftFromRustBuffer[[]FfiFolder](c, rb)
}

func (c FfiConverterSequenceFfiFolder) Read(reader io.Reader) []FfiFolder {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiFolder, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiFolderINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiFolder) Lower(value []FfiFolder) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiFolder](c, value)
}

func (c FfiConverterSequenceFfiFolder) LowerExternal(value []FfiFolder) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiFolder](c, value))
}

func (c FfiConverterSequenceFfiFolder) Write(writer io.Writer, value []FfiFolder) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiFolder is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiFolderINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiFolder struct {}

func (FfiDestroyerSequenceFfiFolder) Destroy(sequence []FfiFolder) {
	for _, value := range sequence {
		FfiDestroyerFfiFolder{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiFolderTreeNode struct{}

var FfiConverterSequenceFfiFolderTreeNodeINSTANCE = FfiConverterSequenceFfiFolderTreeNode{}

func (c FfiConverterSequenceFfiFolderTreeNode) Lift(rb RustBufferI) []FfiFolderTreeNode {
	return LiftFromRustBuffer[[]FfiFolderTreeNode](c, rb)
}

func (c FfiConverterSequenceFfiFolderTreeNode) Read(reader io.Reader) []FfiFolderTreeNode {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiFolderTreeNode, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiFolderTreeNodeINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiFolderTreeNode) Lower(value []FfiFolderTreeNode) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiFolderTreeNode](c, value)
}

func (c FfiConverterSequenceFfiFolderTreeNode) LowerExternal(value []FfiFolderTreeNode) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiFolderTreeNode](c, value))
}

func (c FfiConverterSequenceFfiFolderTreeNode) Write(writer io.Writer, value []FfiFolderTreeNode) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiFolderTreeNode is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiFolderTreeNodeINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiFolderTreeNode struct {}

func (FfiDestroyerSequenceFfiFolderTreeNode) Destroy(sequence []FfiFolderTreeNode) {
	for _, value := range sequence {
		FfiDestroyerFfiFolderTreeNode{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiGroup struct{}

var FfiConverterSequenceFfiGroupINSTANCE = FfiConverterSequenceFfiGroup{}

func (c FfiConverterSequenceFfiGroup) Lift(rb RustBufferI) []FfiGroup {
	return LiftFromRustBuffer[[]FfiGroup](c, rb)
}

func (c FfiConverterSequenceFfiGroup) Read(reader io.Reader) []FfiGroup {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiGroup, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiGroupINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiGroup) Lower(value []FfiGroup) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiGroup](c, value)
}

func (c FfiConverterSequenceFfiGroup) LowerExternal(value []FfiGroup) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiGroup](c, value))
}

func (c FfiConverterSequenceFfiGroup) Write(writer io.Writer, value []FfiGroup) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiGroup is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiGroupINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiGroup struct {}

func (FfiDestroyerSequenceFfiGroup) Destroy(sequence []FfiGroup) {
	for _, value := range sequence {
		FfiDestroyerFfiGroup{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiGroupUser struct{}

var FfiConverterSequenceFfiGroupUserINSTANCE = FfiConverterSequenceFfiGroupUser{}

func (c FfiConverterSequenceFfiGroupUser) Lift(rb RustBufferI) []FfiGroupUser {
	return LiftFromRustBuffer[[]FfiGroupUser](c, rb)
}

func (c FfiConverterSequenceFfiGroupUser) Read(reader io.Reader) []FfiGroupUser {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiGroupUser, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiGroupUserINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiGroupUser) Lower(value []FfiGroupUser) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiGroupUser](c, value)
}

func (c FfiConverterSequenceFfiGroupUser) LowerExternal(value []FfiGroupUser) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiGroupUser](c, value))
}

func (c FfiConverterSequenceFfiGroupUser) Write(writer io.Writer, value []FfiGroupUser) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiGroupUser is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiGroupUserINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiGroupUser struct {}

func (FfiDestroyerSequenceFfiGroupUser) Destroy(sequence []FfiGroupUser) {
	for _, value := range sequence {
		FfiDestroyerFfiGroupUser{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiManagedGroup struct{}

var FfiConverterSequenceFfiManagedGroupINSTANCE = FfiConverterSequenceFfiManagedGroup{}

func (c FfiConverterSequenceFfiManagedGroup) Lift(rb RustBufferI) []FfiManagedGroup {
	return LiftFromRustBuffer[[]FfiManagedGroup](c, rb)
}

func (c FfiConverterSequenceFfiManagedGroup) Read(reader io.Reader) []FfiManagedGroup {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiManagedGroup, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiManagedGroupINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiManagedGroup) Lower(value []FfiManagedGroup) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiManagedGroup](c, value)
}

func (c FfiConverterSequenceFfiManagedGroup) LowerExternal(value []FfiManagedGroup) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiManagedGroup](c, value))
}

func (c FfiConverterSequenceFfiManagedGroup) Write(writer io.Writer, value []FfiManagedGroup) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiManagedGroup is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiManagedGroupINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiManagedGroup struct {}

func (FfiDestroyerSequenceFfiManagedGroup) Destroy(sequence []FfiManagedGroup) {
	for _, value := range sequence {
		FfiDestroyerFfiManagedGroup{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiOwnedItem struct{}

var FfiConverterSequenceFfiOwnedItemINSTANCE = FfiConverterSequenceFfiOwnedItem{}

func (c FfiConverterSequenceFfiOwnedItem) Lift(rb RustBufferI) []FfiOwnedItem {
	return LiftFromRustBuffer[[]FfiOwnedItem](c, rb)
}

func (c FfiConverterSequenceFfiOwnedItem) Read(reader io.Reader) []FfiOwnedItem {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiOwnedItem, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiOwnedItemINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiOwnedItem) Lower(value []FfiOwnedItem) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiOwnedItem](c, value)
}

func (c FfiConverterSequenceFfiOwnedItem) LowerExternal(value []FfiOwnedItem) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiOwnedItem](c, value))
}

func (c FfiConverterSequenceFfiOwnedItem) Write(writer io.Writer, value []FfiOwnedItem) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiOwnedItem is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiOwnedItemINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiOwnedItem struct {}

func (FfiDestroyerSequenceFfiOwnedItem) Destroy(sequence []FfiOwnedItem) {
	for _, value := range sequence {
		FfiDestroyerFfiOwnedItem{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiPermission struct{}

var FfiConverterSequenceFfiPermissionINSTANCE = FfiConverterSequenceFfiPermission{}

func (c FfiConverterSequenceFfiPermission) Lift(rb RustBufferI) []FfiPermission {
	return LiftFromRustBuffer[[]FfiPermission](c, rb)
}

func (c FfiConverterSequenceFfiPermission) Read(reader io.Reader) []FfiPermission {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiPermission, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiPermissionINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiPermission) Lower(value []FfiPermission) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiPermission](c, value)
}

func (c FfiConverterSequenceFfiPermission) LowerExternal(value []FfiPermission) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiPermission](c, value))
}

func (c FfiConverterSequenceFfiPermission) Write(writer io.Writer, value []FfiPermission) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiPermission is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiPermissionINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiPermission struct {}

func (FfiDestroyerSequenceFfiPermission) Destroy(sequence []FfiPermission) {
	for _, value := range sequence {
		FfiDestroyerFfiPermission{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiResource struct{}

var FfiConverterSequenceFfiResourceINSTANCE = FfiConverterSequenceFfiResource{}

func (c FfiConverterSequenceFfiResource) Lift(rb RustBufferI) []FfiResource {
	return LiftFromRustBuffer[[]FfiResource](c, rb)
}

func (c FfiConverterSequenceFfiResource) Read(reader io.Reader) []FfiResource {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiResource, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiResourceINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiResource) Lower(value []FfiResource) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiResource](c, value)
}

func (c FfiConverterSequenceFfiResource) LowerExternal(value []FfiResource) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiResource](c, value))
}

func (c FfiConverterSequenceFfiResource) Write(writer io.Writer, value []FfiResource) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiResource is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiResourceINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiResource struct {}

func (FfiDestroyerSequenceFfiResource) Destroy(sequence []FfiResource) {
	for _, value := range sequence {
		FfiDestroyerFfiResource{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiResourceType struct{}

var FfiConverterSequenceFfiResourceTypeINSTANCE = FfiConverterSequenceFfiResourceType{}

func (c FfiConverterSequenceFfiResourceType) Lift(rb RustBufferI) []FfiResourceType {
	return LiftFromRustBuffer[[]FfiResourceType](c, rb)
}

func (c FfiConverterSequenceFfiResourceType) Read(reader io.Reader) []FfiResourceType {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiResourceType, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiResourceTypeINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiResourceType) Lower(value []FfiResourceType) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiResourceType](c, value)
}

func (c FfiConverterSequenceFfiResourceType) LowerExternal(value []FfiResourceType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiResourceType](c, value))
}

func (c FfiConverterSequenceFfiResourceType) Write(writer io.Writer, value []FfiResourceType) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiResourceType is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiResourceTypeINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiResourceType struct {}

func (FfiDestroyerSequenceFfiResourceType) Destroy(sequence []FfiResourceType) {
	for _, value := range sequence {
		FfiDestroyerFfiResourceType{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiSecret struct{}

var FfiConverterSequenceFfiSecretINSTANCE = FfiConverterSequenceFfiSecret{}

func (c FfiConverterSequenceFfiSecret) Lift(rb RustBufferI) []FfiSecret {
	return LiftFromRustBuffer[[]FfiSecret](c, rb)
}

func (c FfiConverterSequenceFfiSecret) Read(reader io.Reader) []FfiSecret {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiSecret, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiSecretINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiSecret) Lower(value []FfiSecret) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiSecret](c, value)
}

func (c FfiConverterSequenceFfiSecret) LowerExternal(value []FfiSecret) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiSecret](c, value))
}

func (c FfiConverterSequenceFfiSecret) Write(writer io.Writer, value []FfiSecret) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiSecret is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiSecretINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiSecret struct {}

func (FfiDestroyerSequenceFfiSecret) Destroy(sequence []FfiSecret) {
	for _, value := range sequence {
		FfiDestroyerFfiSecret{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiTag struct{}

var FfiConverterSequenceFfiTagINSTANCE = FfiConverterSequenceFfiTag{}

func (c FfiConverterSequenceFfiTag) Lift(rb RustBufferI) []FfiTag {
	return LiftFromRustBuffer[[]FfiTag](c, rb)
}

func (c FfiConverterSequenceFfiTag) Read(reader io.Reader) []FfiTag {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiTag, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiTagINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiTag) Lower(value []FfiTag) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiTag](c, value)
}

func (c FfiConverterSequenceFfiTag) LowerExternal(value []FfiTag) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiTag](c, value))
}

func (c FfiConverterSequenceFfiTag) Write(writer io.Writer, value []FfiTag) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiTag is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiTagINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiTag struct {}

func (FfiDestroyerSequenceFfiTag) Destroy(sequence []FfiTag) {
	for _, value := range sequence {
		FfiDestroyerFfiTag{}.Destroy(value)	
	}
}


type FfiConverterSequenceFfiUser struct{}

var FfiConverterSequenceFfiUserINSTANCE = FfiConverterSequenceFfiUser{}

func (c FfiConverterSequenceFfiUser) Lift(rb RustBufferI) []FfiUser {
	return LiftFromRustBuffer[[]FfiUser](c, rb)
}

func (c FfiConverterSequenceFfiUser) Read(reader io.Reader) []FfiUser {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FfiUser, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterFfiUserINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceFfiUser) Lower(value []FfiUser) C.RustBuffer {
	return LowerIntoRustBuffer[[]FfiUser](c, value)
}

func (c FfiConverterSequenceFfiUser) LowerExternal(value []FfiUser) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]FfiUser](c, value))
}

func (c FfiConverterSequenceFfiUser) Write(writer io.Writer, value []FfiUser) {
	if len(value) > math.MaxInt32 {
		panic("[]FfiUser is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterFfiUserINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceFfiUser struct {}

func (FfiDestroyerSequenceFfiUser) Destroy(sequence []FfiUser) {
	for _, value := range sequence {
		FfiDestroyerFfiUser{}.Destroy(value)	
	}
}

func DecryptMessage(armoredMessage string, privateKeyArmored string, passphrase string) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_func_decrypt_message(FfiConverterStringINSTANCE.Lower(armoredMessage), FfiConverterStringINSTANCE.Lower(privateKeyArmored), FfiConverterStringINSTANCE.Lower(passphrase),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue []byte
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
		}
}

// Encrypt a plaintext message for one or more PGP public keys.
// Returns the PGP-armored ciphertext.
func EncryptMessage(plaintext []byte, publicKeysArmored []string) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_func_encrypt_message(FfiConverterBytesINSTANCE.Lower(plaintext), FfiConverterSequenceStringINSTANCE.Lower(publicKeysArmored),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue string
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
		}
}

// The server public key, to pin in [`FfiLoginOptions::server_public_key`] once the user
// confirmed its fingerprint.
func FetchServerKey(serverUrl string, tlsSkipVerify bool) (FfiServerKey, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_func_fetch_server_key(FfiConverterStringINSTANCE.Lower(serverUrl), FfiConverterBoolINSTANCE.Lower(tlsSkipVerify),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue FfiServerKey
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterFfiServerKeyINSTANCE.Lift(_uniffiRV), nil
		}
}

// Parse a PGP private key and return its fingerprint (hex uppercase).
func GetKeyFingerprint(privateKeyArmored string) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[PassboltFfiError](FfiConverterPassboltFfiError{},func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer {
		inner: C.uniffi_passbolt_ffi_fn_func_get_key_fingerprint(FfiConverterStringINSTANCE.Lower(privateKeyArmored),_uniffiStatus),
	}
	})
		if _uniffiErr != nil {
			var _uniffiDefaultValue string
			return _uniffiDefaultValue, _uniffiErr
		} else {
			return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
		}
}

