//go:build darwin

package agent

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func verifyPeer(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("not a Unix connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Xucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		credential, peerErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if credential == nil || int(credential.Uid) != os.Getuid() {
		return errors.New("agent peer UID mismatch")
	}
	return nil
}
