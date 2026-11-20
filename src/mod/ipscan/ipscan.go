package ipscan

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"imuslab.com/zoraxy/mod/destguard"
)

/*
	IP Scanner

	This module scan the given network range and return a list
	of nearby nodes.
*/

type DiscoveredHost struct {
	IP                string
	Ping              int
	Hostname          string
	HttpPortDetected  bool
	HttpsPortDetected bool
}

const maxConcurrentPings = 64

// Scan an IP range given the start and ending ip address
func ScanIpRange(start, end string) ([]*DiscoveredHost, error) {
	ipStart := net.ParseIP(start)
	ipEnd := net.ParseIP(end)
	if ipStart == nil || ipEnd == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	if bytes.Compare(ipStart, ipEnd) > 0 {
		return nil, fmt.Errorf("invalid IP range")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	// Limit concurrent pings; too many ICMP sockets at once causes
	// replies to be dropped (especially on macOS)
	pingLimiter := make(chan struct{}, maxConcurrentPings)
	hosts := make([]*DiscoveredHost, 0)
	var firstRefusal error
	for ip := ipStart; bytes.Compare(ip, ipEnd) <= 0; inc(ip) {
		thisIp := ip.String()
		//Destination restriction (off by default): loopback, link-local, metadata and unlisted hosts are not probed
		if err := CheckTarget(thisIp); err != nil {
			if firstRefusal == nil {
				firstRefusal = err
			}
			continue
		}
		wg.Add(1)
		go func(thisIp string) {
			defer wg.Done()
			host := &DiscoveredHost{IP: thisIp}
			pingLimiter <- struct{}{}
			err := host.CheckPing()
			<-pingLimiter
			if err != nil {
				// skip if the host is unreachable
				host.Ping = -1
				mu.Lock()
				hosts = append(hosts, host)
				mu.Unlock()
				return
			}

			host.CheckHostname()
			host.CheckPort("http", 80, &host.HttpPortDetected)
			host.CheckPort("https", 443, &host.HttpsPortDetected)
			mu.Lock()
			hosts = append(hosts, host)
			mu.Unlock()

		}(thisIp)
	}

	//Wait until all go routine done
	wg.Wait()
	if firstRefusal != nil && len(hosts) == 0 {
		return nil, firstRefusal
	}
	sortByIP(hosts)
	return hosts, nil
}

// CheckTarget applies the destination restriction (mod/destguard) to one scan target; nil when it is off or allowed
func CheckTarget(host string) error {
	if !destguard.Restricting() {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%q is not an IP address", host)
	}
	return destguard.CheckDest(ip, 0)
}

func ScanCIDRRange(cidr string) ([]*DiscoveredHost, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip := ipNet.IP.To4()
	startIP := net.IPv4(ip[0], ip[1], ip[2], 1).String()
	endIP := net.IPv4(ip[0], ip[1], ip[2], 254).String()

	return ScanIpRange(startIP, endIP)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func sortByIP(discovered []*DiscoveredHost) {
	sort.Slice(discovered, func(i, j int) bool {
		return discovered[i].IP < discovered[j].IP
	})
}

func (host *DiscoveredHost) CheckPing() error {
	// macOS does not allow raw ICMP sockets without root, but supports
	// unprivileged (datagram) ICMP out of the box. Other platforms default
	// to privileged mode and fall back to unprivileged if that fails.
	privileged := runtime.GOOS != "darwin"
	stats, err := pingHost(host.IP, privileged)
	if err != nil {
		stats, err = pingHost(host.IP, !privileged)
		if err != nil {
			return err
		}
	}
	if stats.PacketsRecv == 0 {
		return fmt.Errorf("host unreachable for %s", host.IP)
	}
	host.Ping = int(stats.AvgRtt.Milliseconds())
	return nil
}

func pingHost(ip string, privileged bool) (*ping.Statistics, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return nil, err
	}
	pinger.Count = 4
	pinger.Timeout = time.Second
	pinger.SetPrivileged(privileged)
	if err := pinger.Run(); err != nil {
		return nil, err
	}
	return pinger.Statistics(), nil
}

func (host *DiscoveredHost) CheckHostname() {
	// lookup the hostname for the IP address
	names, err := net.LookupAddr(host.IP)
	//fmt.Println(names, err)
	if err == nil && len(names) > 0 {
		host.Hostname = names[0]
	}
}

func (host *DiscoveredHost) CheckPort(protocol string, port int, detected *bool) {
	// try to connect to the specified port on the host
	conn, err := destguard.DialTimeout("tcp", net.JoinHostPort(host.IP, strconv.Itoa(port)), 1*time.Second)
	if err == nil {
		conn.Close()
		*detected = true
	}
}

func (host *DiscoveredHost) ScanPorts(startPort, endPort int) []int {
	var openPorts []int

	for port := startPort; port <= endPort; port++ {
		target := net.JoinHostPort(host.IP, fmt.Sprintf("%d", port))
		conn, err := destguard.DialTimeout("tcp", target, time.Millisecond*500)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}
