package loopback

/*
#include <linux/loop.h>
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

type (
	LoopInfo64 struct {
		loDevice           uint64 /* ioctl r/o */
		loInode            uint64 /* ioctl r/o */
		loRdevice          uint64 /* ioctl r/o */
		loOffset           uint64
		loSizelimit        uint64 /* bytes, 0 == max available */
		loNumber           uint32 /* ioctl r/o */
		loEncrypt_type     uint32
		loEncrypt_key_size uint32 /* ioctl w/o */
		loFlags            uint32 /* ioctl r/o */
		loFileName         [LoNameSize]uint8
		loCryptName        [LoNameSize]uint8
		loEncryptKey       [LoKeySize]uint8 /* ioctl w/o */
		loInit             [2]uint64
	}
)

// IOCTL consts
const (
	LoopSetFd       = C.LOOP_SET_FD
	LoopCtlGetFree  = C.LOOP_CTL_GET_FREE
	LoopGetStatus64 = C.LOOP_GET_STATUS64
	LoopSetStatus64 = C.LOOP_SET_STATUS64
	LoopClrFd       = C.LOOP_CLR_FD
	LoopSetCapacity = C.LOOP_SET_CAPACITY
)

const (
	LoFlagsAutoClear = C.LO_FLAGS_AUTOCLEAR
	LoFlagsReadOnly  = C.LO_FLAGS_READ_ONLY
	LoFlagsPartScan  = C.LO_FLAGS_PARTSCAN
	LoKeySize        = C.LO_KEY_SIZE
	LoNameSize       = C.LO_NAME_SIZE
)

// syscalls will return an errno type (which implements error) for all calls,
// including success (errno 0). We only care about non-zero errnos.
func errnoIsErr(err error) error {
	if err.(syscall.Errno) != 0 {
		return err
	}
	return nil
}

// Given a handle to a Loopback device (such as /dev/loop0), and a handle
// to the image to loop mount (such as a squashfs or ext4fs image), preform
// the required call to loop the image to the provided block device.
func Loop(loopbackDevice, image *os.File) error {
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		loopbackDevice.Fd(),
		LoopSetFd,
		image.Fd(),
	)
	return errnoIsErr(err)
}

// Given a handle to the Loopback device (such as /dev/loop0), preform the
// required call to the image to unloop the file.
func Unloop(loopbackDevice *os.File) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, loopbackDevice.Fd(), LoopClrFd, 0)
	return errnoIsErr(err)
}

// Get the next loopback device that isn't used. Under the hood this will ask
// loop-control for the LOOP_CTL_GET_FREE value, and interpolate that into
// the conventional GNU/Linux naming scheme for loopback devices, and os.Open
// that path.
func NextLoopDevice() (*os.File, error) {
	loopInt, err := nextUnallocatedLoop()
	if err != nil {
		return nil, err
	}
	return os.Open(fmt.Sprintf("/dev/loop%d", loopInt))
}

// Return the integer of the next loopback device we can use by calling
// loop-control with the LOOP_CTL_GET_FREE ioctl.
func nextUnallocatedLoop() (int, error) {
	fd, err := os.OpenFile("/dev/loop-control", os.O_RDONLY, 0644)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	index, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), LoopCtlGetFree, 0)
	return int(index), errnoIsErr(err)
}

// Get the next loopback device that isn't used, loopback the image,
// and mount the loopback device to the target.
func MountImage(
	image *os.File,

	target string,
	fstype string,
	flags uintptr,
	data string,
) (*os.File, func(), error) {
	lo, err := NextLoopDevice()
	if err != nil {
		log.Println("n loop")
		return nil, nil, err
	}

	if err := Loop(lo, image); err != nil {
		log.Println("loop")
		lo.Close()
		return nil, nil, err
	}

	if err := syscall.Mount(lo.Name(), target, fstype, flags, data); err != nil {
		log.Println("mount")
		Unloop(lo)
		lo.Close()
		return nil, nil, err
	}

	return lo, func() {
		syscall.Unmount(target, 0)
		Unloop(lo)
		lo.Close()
	}, nil
}
