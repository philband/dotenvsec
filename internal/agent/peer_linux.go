//go:build linux

package agent

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
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
	var cred *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if int(cred.Uid) != os.Getuid() {
		return errors.New("agent peer UID mismatch")
	}
	return nil
}
