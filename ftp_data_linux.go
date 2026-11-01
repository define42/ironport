//go:build linux

package ironport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

func parseFTPPassivePortRange(portRange string) (start, end int, err error) {
	portRange = strings.TrimSpace(portRange)
	if portRange == "" {
		return 0, 0, nil
	}

	if !strings.Contains(portRange, "-") {
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid FTP passive port %q", portRange)
		}
		if port < 1 || port > 65535 {
			return 0, 0, fmt.Errorf("FTP passive port %q out of range", portRange)
		}
		return port, port, nil
	}

	startText, endText, _ := strings.Cut(portRange, "-")
	start, err = strconv.Atoi(strings.TrimSpace(startText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid FTP passive port range %q", portRange)
	}
	end, err = strconv.Atoi(strings.TrimSpace(endText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid FTP passive port range %q", portRange)
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("FTP passive port range %q out of range", portRange)
	}
	return start, end, nil
}

func (s *Server) listenFTPData(host string) (net.Listener, error) {
	portRange := strings.TrimSpace(s.ftpPassivePortRange)
	if portRange == "" {
		return net.Listen("tcp", net.JoinHostPort(host, "0"))
	}

	start, end, err := parseFTPPassivePortRange(portRange)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all FTP passive ports in range %q are unavailable: %w", portRange, lastErr)
}

func (f *ftpSession) cmdEpsv(arg string) {
	if strings.EqualFold(strings.TrimSpace(arg), "ALL") {
		f.closeDataEndpoint()
		f.epsvAll = true
		_ = f.reply(200, "EPSV ALL ok")
		return
	}
	f.enterPassive(true)
}

func (f *ftpSession) enterPassive(epsv bool) {
	f.closeDataEndpoint()

	host, _, err := net.SplitHostPort(f.conn.LocalAddr().String())
	if err != nil || host == "" {
		_ = f.reply(425, "cannot determine local address")
		return
	}

	ip := net.ParseIP(host)
	if !epsv && ip.To4() == nil {
		_ = f.reply(522, "network protocol not supported, use EPSV")
		return
	}

	ln, err := f.server.listenReservedFTPData(host, f.username, f.clientIP)
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	f.dataMu.Lock()
	if f.cancelled {
		f.dataMu.Unlock()
		_ = ln.Close()
		return
	}
	f.dataLn = ln
	f.dataMu.Unlock()

	port := ln.Addr().(*net.TCPAddr).Port
	if epsv {
		_ = f.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		return
	}

	v4 := ip.To4()
	// Behind NAT the control connection's local IP is the internal address;
	// advertise the configured external IPv4 address instead when one is set
	// so the client dials an address it can actually reach.
	if adv := f.server.passiveAdvertisedIPv4(); adv != nil {
		v4 = adv
	}
	p1 := port / 256
	p2 := port % 256
	_ = f.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", v4[0], v4[1], v4[2], v4[3], p1, p2))
}

// passiveAdvertisedIPv4 returns the configured PASV advertised address as a
// 4-byte IPv4 value, or nil when none is configured or the configured value
// is not a valid IPv4 address.
func (s *Server) passiveAdvertisedIPv4() net.IP {
	if s.ftpPassiveAdvertisedIP == "" {
		return nil
	}
	return net.ParseIP(s.ftpPassiveAdvertisedIP).To4()
}

func (f *ftpSession) enterActivePORT(arg string) {
	f.closeDataEndpoint()
	if !f.activeModeAllowed() {
		_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
		return
	}

	addr, err := parseFTPPORTArg(arg)
	if err != nil {
		_ = f.reply(501, "invalid PORT")
		return
	}
	f.enterActive(addr)
}

func (f *ftpSession) enterActiveEPRT(arg string) {
	f.closeDataEndpoint()
	if !f.activeModeAllowed() {
		_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
		return
	}

	addr, err := parseFTPEPRTArg(arg)
	if err != nil {
		_ = f.reply(501, "invalid EPRT")
		return
	}
	f.enterActive(addr)
}

func (f *ftpSession) activeModeAllowed() bool {
	return f.server.ftpAllowActiveMode && !f.epsvAll
}

func (f *ftpSession) enterActive(addr *net.TCPAddr) {
	if !f.activeTargetAllowed(addr.IP) {
		_ = f.reply(501, "active target address not allowed")
		return
	}
	f.closeDataEndpoint()
	f.dataMu.Lock()
	if !f.cancelled {
		f.dataAddr = addr
	}
	f.dataMu.Unlock()
	_ = f.reply(200, "active mode ready")
}

func (f *ftpSession) activeTargetAllowed(ip net.IP) bool {
	clientIP := net.ParseIP(f.clientIP)
	return clientIP != nil && ip != nil && ip.Equal(clientIP)
}

func parseFTPPORTArg(arg string) (*net.TCPAddr, error) {
	parts := strings.Split(strings.TrimSpace(arg), ",")
	if len(parts) != 6 {
		return nil, errors.New("invalid PORT")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 0 || n > 255 {
			return nil, errors.New("invalid PORT")
		}
		values[i] = n
	}
	port := values[4]*256 + values[5]
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid PORT")
	}
	return &net.TCPAddr{
		// Each value is already validated to be in [0,255] above, so the byte
		// conversion cannot overflow.
		IP:   net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])), //nolint:gosec // values bounded to [0,255]
		Port: port,
	}, nil
}

func parseFTPEPRTArg(arg string) (*net.TCPAddr, error) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 5 {
		return nil, errors.New("invalid EPRT")
	}
	delim := arg[:1]
	parts := strings.Split(arg[1:], delim)
	if len(parts) != 4 || parts[3] != "" {
		return nil, errors.New("invalid EPRT")
	}
	family, addrText, portText := parts[0], parts[1], parts[2]
	ip := net.ParseIP(addrText)
	if ip == nil {
		return nil, errors.New("invalid EPRT")
	}
	switch family {
	case "1":
		ip = ip.To4()
		if ip == nil {
			return nil, errors.New("invalid EPRT")
		}
	case "2":
		if ip.To4() != nil {
			return nil, errors.New("invalid EPRT")
		}
	default:
		return nil, errors.New("invalid EPRT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("invalid EPRT")
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func (f *ftpSession) acceptDataConn() (net.Conn, error) {
	if f.server.ftpRequireTLS && f.dataProt != 'P' {
		f.closeDataEndpoint()
		return nil, errFTPDataProtectionRequired
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.dataMu.Lock()
	if f.cancelled || f.controlReadClosed {
		f.dataMu.Unlock()
		return nil, net.ErrClosed
	}
	f.dataCancel = cancel
	ln, addr := f.dataLn, f.dataAddr
	f.dataMu.Unlock()
	// Keep the passive permit through FTPS authentication, then release the
	// listening port before starting the established transfer.
	defer f.finishDataSetup()
	var deadline time.Time
	if timeout := f.server.effectiveFTPDataAcceptTimeout(); timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if reserved, ok := ln.(*netconn.ExpiringListener); ok {
		// PASV/EPSV starts the absolute lifetime; later commands cannot extend it.
		deadline = reserved.Deadline()
	}
	dc, err := f.dialOrAcceptDataConn(ctx, ln, addr, deadline)
	if err != nil {
		return nil, err
	}
	return f.protectDataConn(ctx, dc, deadline)
}

func (f *ftpSession) protectDataConn(ctx context.Context, dc net.Conn, setupDeadline time.Time) (net.Conn, error) {
	f.dataMu.Lock()
	if f.cancelled || f.controlReadClosed {
		f.dataMu.Unlock()
		_ = dc.Close()
		return nil, net.ErrClosed
	}
	f.dataConn = dc
	f.dataMu.Unlock()
	if f.dataProt != 'P' {
		return dc, nil
	}
	// PROT P uses this control session's private data config, which requires
	// resumption of its own ticket. The handshake is part of setup and cannot
	// outlive the passive reservation.
	if f.dataTLSConfig == nil {
		_ = dc.Close()
		return nil, errors.New("PROT P requested but FTPS is not configured")
	}
	deadline := time.Now().Add(ftpTLSHandshakeTimeout)
	if !setupDeadline.IsZero() && setupDeadline.Before(deadline) {
		deadline = setupDeadline
	}
	_ = dc.SetDeadline(deadline)
	tc := tls.Server(dc, f.dataTLSConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = dc.Close()
		return nil, fmt.Errorf("data tls handshake: %w", err)
	}
	_ = dc.SetDeadline(time.Time{})
	return tc, nil
}

func (f *ftpSession) dialOrAcceptDataConn(ctx context.Context, ln net.Listener, addr *net.TCPAddr, deadline time.Time) (net.Conn, error) {
	if ln != nil {
		return f.acceptPassiveDataConn(ln, deadline)
	}
	if addr != nil {
		return f.dialActiveDataConn(ctx, addr, deadline)
	}
	return nil, errors.New("data connection not prepared")
}

func (f *ftpSession) acceptPassiveDataConn(ln net.Listener, deadline time.Time) (net.Conn, error) {
	if tcpLn, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		_ = tcpLn.SetDeadline(deadline)
	}
	dc, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	// Prevent passive data-port stealing by requiring the control peer's IP.
	if f.clientIP != "" && netconn.RemoteIP(dc.RemoteAddr()) != f.clientIP {
		_ = dc.Close()
		return nil, fmt.Errorf("data connection from unexpected IP %s", netconn.RemoteIP(dc.RemoteAddr()))
	}
	return dc, nil
}

func (f *ftpSession) dialActiveDataConn(ctx context.Context, addr *net.TCPAddr, deadline time.Time) (net.Conn, error) {
	dialer := net.Dialer{Deadline: deadline}
	log.Printf("ftp active data dial user=%s from=%s to=%s", f.username, f.conn.RemoteAddr(), addr)
	return dialer.DialContext(ctx, "tcp", addr.String())
}

// closeDataConn closes an FTP data connection. For TLS-wrapped data
// connections it first sends a close_notify alert via CloseWrite, so the
// client can distinguish "transfer complete, stream closed cleanly" from
// "TCP RST mid-stream that may have truncated the payload". This is
// required by TLS for unambiguous EOF; without it a malicious party that
// injects a TCP FIN could trick the client into accepting a truncated
// download as complete.
//
// For plain TCP data connections CloseWrite is unnecessary because FTP
// STREAM mode already conveys EOF via the TCP FIN, and io.Copy on the
// receiver returns a clean EOF when that arrives. Calling tls.Conn's
// CloseWrite is best-effort: any error is intentionally ignored because
// the subsequent Close will tear the connection down anyway.
func closeDataConn(dc net.Conn) {
	if tc, ok := dc.(*tls.Conn); ok {
		_ = tc.CloseWrite()
	}
	_ = dc.Close()
}

func (f *ftpSession) closeDataListener() {
	f.dataMu.Lock()
	ln := f.dataLn
	f.dataLn = nil
	f.dataMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func (f *ftpSession) closeDataEndpoint() {
	f.closeDataListener()
	f.dataMu.Lock()
	f.dataAddr = nil
	f.dataMu.Unlock()
}

func (f *ftpSession) finishDataSetup() {
	f.closeDataEndpoint()
	f.dataMu.Lock()
	f.dataCancel = nil
	f.dataMu.Unlock()
}

// A control-reader EOF interrupts pending setup while queued commands still
// receive their replies. Established transfers consume EOF in runTransfer.
func (f *ftpSession) controlReaderClosed() {
	f.dataMu.Lock()
	f.controlReadClosed = true
	ln, dc, cancel := f.dataLn, f.dataConn, f.dataCancel
	f.dataMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if ln != nil {
		_ = ln.Close()
	}
	if dc != nil {
		_ = dc.Close()
	}
}

// cancelDataOperations releases reservations and interrupts setup/transfer I/O
// when this control connection is revoked, shut down, or finally torn down.
func (f *ftpSession) cancelDataOperations() {
	f.dataMu.Lock()
	f.cancelled = true
	ln, dc, cancel := f.dataLn, f.dataConn, f.dataCancel
	f.dataLn, f.dataConn, f.dataCancel = nil, nil, nil
	f.dataAddr = nil
	f.dataMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	if dc != nil {
		_ = dc.Close()
	}
}
