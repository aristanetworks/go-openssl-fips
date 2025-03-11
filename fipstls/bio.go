package fipstls

import (
	"fmt"
	"net"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// BIO is the basic I/O abstraction used by [Conn] for reading from and writing to sockets.
type BIO struct {
	bio        *libssl.BIO
	closer     Closer
	hostname   string
	port       string
	sockfd     int
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (b *BIO) String() string {
	return fmt.Sprintf("%-20s %-20s %-5s",
		fmt.Sprintf("local=%+v", b.localAddr),
		fmt.Sprintf("remote=%+v", b.remoteAddr),
		fmt.Sprintf("conn=%+v", b.sockfd))
}

const (
	SOCK_BLOCK = iota
	SOCK_NONBLOCK
)

// NewBIO will create a new [libssl.BIO] connected to the host. It can be either blocking (mode=0)
// or non-blocking (mode=1).
func NewBIO(addr, network string, mode int) (b *BIO, err error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	b = &BIO{closer: noopCloser{}}
	b.hostname, b.port, err = net.SplitHostPort(addr)
	if err != nil {
		return b, err
	}
	family, err := parseNetwork(network)
	if err != nil {
		return b, err
	}
	b.bio, b.sockfd, err = libssl.CreateBIO(b.hostname, b.port, family, mode)
	if err != nil {
		return b, err
	}
	if err := b.setAddrInfo(); err != nil {
		return b, err
	}
	b.closer = newOnceCloser(func() error {
		if b.bio == nil {
			return nil
		}
		return libssl.BIOFree(b.bio)
	})
	return b, nil
}

func parseNetwork(network string) (int, error) {
	switch network {
	case "tcp", "tcp4":
		return syscall.AF_INET, nil
	case "tcp6":
		return syscall.AF_INET6, nil
	case "unix":
		return syscall.AF_UNIX, nil
	default:
		return 0, net.UnknownNetworkError(network)
	}
}

// setAddrInfo initializes the local and remote addresses of the [BIO] socket connection.
func (b *BIO) setAddrInfo() (err error) {
	sockname, err := syscall.Getsockname(b.sockfd)
	if err != nil {
		return err
	}
	peername, err := syscall.Getpeername(b.sockfd)
	if err != nil {
		return err
	}
	b.localAddr, b.remoteAddr = sockaddrToNetAddr(sockname), sockaddrToNetAddr(peername)
	return nil
}

func sockaddrToNetAddr(sa syscall.Sockaddr) net.Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: int(sa.Port),
		}
	case *syscall.SockaddrInet6:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: int(sa.Port),
			Zone: zoneToString(int(sa.ZoneId)),
		}
	case *syscall.SockaddrUnix:
		return &net.UnixAddr{
			Name: sa.Name,
			Net:  "unix",
		}
	default:
		return nil
	}
}

func zoneToString(zone int) string {
	if zone == 0 {
		return ""
	}
	if ifi, err := net.InterfaceByIndex(zone); err == nil {
		return ifi.Name
	}
	return fmt.Sprintf("%d", zone)
}

// BIO returns a pointer to the underlying [libssl.BIO] C object.
func (b *BIO) BIO() *libssl.BIO {
	return b.bio
}

// Hostname returns the peer hostname.
func (b *BIO) Hostname() string {
	return b.hostname
}

// LocalAddr returns the local address if known.
func (b *BIO) LocalAddr() net.Addr {
	return b.localAddr
}

// RemoteAddr returns the peer address if known.
func (b *BIO) RemoteAddr() net.Addr {
	return b.remoteAddr
}

// FD returns the socket file descriptor.
func (b *BIO) FD() int {
	return b.sockfd
}

// CloseFD will close the socket file descriptor.
func (b *BIO) CloseFD() error {
	return syscall.Close(b.sockfd)
}

// Close frees the [libssl.BIO] object allocated for [BIO].
func (b *BIO) Close() error {
	return b.closer.Close()
}
