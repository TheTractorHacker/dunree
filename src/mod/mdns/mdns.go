package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/foleyit/dunree/mod/utils"
	"github.com/grandcat/zeroconf"
)

type MDNSHost struct {
	MDNS          *zeroconf.Server
	aliases       []*zeroconf.Server //further instance names of this host (RegisterAlias)
	txt           []string
	Host          *NetworkHost
	IfaceOverride *net.Interface
}

type NetworkHost struct {
	HostName     string
	Port         int
	IPv4         []net.IP
	Domain       string
	Model        string
	UUID         string
	Vendor       string
	BuildVersion string
	MacAddr      []string
	Online       bool
}

// Create a new MDNS discoverer, set MacOverride to empty string for using the first NIC discovered
func NewMDNS(config NetworkHost, MacOverride string) (*MDNSHost, error) {
	//Get host MAC Address
	macAddress, err := getMacAddr()
	if err != nil {
		return nil, err
	}

	macAddressBoardcast := ""
	if err == nil {
		macAddressBoardcast = strings.Join(macAddress, ",")
	} else {
		log.Println("[mDNS] Unable to get MAC Address: ", err.Error())
	}

	//Register the mds services
	server, err := zeroconf.Register(config.HostName, "_http._tcp", "local.", config.Port, []string{"version_build=" + config.BuildVersion, "vendor=" + config.Vendor, "model=" + config.Model, "uuid=" + config.UUID, "domain=" + config.Domain, "mac_addr=" + macAddressBoardcast}, nil)
	if err != nil {
		log.Println("[mDNS] Error when registering zeroconf broadcast message", err.Error())
		return &MDNSHost{}, err
	}

	//Discover the iface to override if exists
	var overrideIface *net.Interface = nil
	if MacOverride != "" {
		ifaceIp := ""
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Println("[mDNS] Unable to override iface MAC: " + err.Error() + ". Resuming with default iface")
		}

		foundMatching := false
		for _, iface := range ifaces {
			thisIfaceMac := iface.HardwareAddr.String()
			thisIfaceMac = strings.ReplaceAll(thisIfaceMac, ":", "-")
			MacOverride = strings.ReplaceAll(MacOverride, ":", "-")
			if strings.EqualFold(thisIfaceMac, strings.TrimSpace(MacOverride)) {
				//This is the correct iface to use
				overrideIface = &iface
				addrs, err := iface.Addrs()

				if err == nil && len(addrs) > 0 {
					ifaceIp = addrs[0].String()
				}

				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}

					if ip.To4() != nil {
						//This NIC have Ipv4 addr
						ifaceIp = ip.String()
					}
				}
				foundMatching = true
				break
			}
		}

		if !foundMatching {
			log.Println("[mDNS] Unable to find the target iface with MAC address: " + MacOverride + ". Resuming with default iface")
		} else {
			log.Println("[mDNS] Entering force MAC address mode, listening on: " + MacOverride + "(IP address: " + ifaceIp + ")")
		}
	}

	return &MDNSHost{
		MDNS:          server,
		txt:           []string{"version_build=" + config.BuildVersion, "vendor=" + config.Vendor, "model=" + config.Model, "uuid=" + config.UUID, "domain=" + config.Domain, "mac_addr=" + macAddressBoardcast},
		Host:          &config,
		IfaceOverride: overrideIface,
	}, nil
}

func (m *MDNSHost) Close() {
	if m == nil {
		return
	}
	if m.MDNS != nil {
		m.MDNS.Shutdown()
	}
	for _, a := range m.aliases {
		a.Shutdown()
	}
}

// RegisterAlias announces the same service under a second instance name (same port and TXT
// record), for example the name an older build of this host was known by.
func (m *MDNSHost) RegisterAlias(instance string) error {
	if m == nil || m.Host == nil {
		return fmt.Errorf("mDNS is not running")
	}
	s, err := zeroconf.Register(instance, "_http._tcp", "local.", m.Host.Port, m.txt, nil)
	if err != nil {
		return err
	}
	m.aliases = append(m.aliases, s)
	return nil
}

// Scan with given timeout and domain filter. Use m.Host.Domain for scanning similar typed devices
func (m *MDNSHost) Scan(timeout int, domainFilter string) []*NetworkHost {
	// Discover all services on the network (e.g. _workstation._tcp)

	var zcoption zeroconf.ClientOption = nil
	if m.IfaceOverride != nil {
		zcoption = zeroconf.SelectIfaces([]net.Interface{*m.IfaceOverride})
	}

	resolver, err := zeroconf.NewResolver(zcoption)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	//Create go routine  to wait for the resolver

	discoveredHost := []*NetworkHost{}

	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if domainFilter == "" {
				//No domain filter: read the identity properties of every host that answers
				//Split the required information out of the text element
				TEXT := entry.Text
				properties := map[string]string{}
				for _, v := range TEXT {
					kv := strings.Split(v, "=")
					if len(kv) == 2 {
						properties[kv[0]] = kv[1]
					}
				}

				var macAddrs []string
				val, ok := properties["mac_addr"]
				if !ok || val == "" {
					//No MacAddr found. Target node version too old
					macAddrs = []string{}
				} else {
					macAddrs = strings.Split(properties["mac_addr"], ",")
				}

				//log.Println(properties)
				discoveredHost = appendUniqueHost(discoveredHost, &NetworkHost{
					HostName:     entry.HostName,
					Port:         entry.Port,
					IPv4:         entry.AddrIPv4,
					Domain:       properties["domain"],
					Model:        properties["model"],
					UUID:         properties["uuid"],
					Vendor:       properties["vendor"],
					BuildVersion: properties["version_build"],
					MacAddr:      macAddrs,
					Online:       true,
				})

			} else {
				if utils.StringInArray(entry.Text, "domain="+domainFilter) {
					//This is generic scan request
					//Split the required information out of the text element
					TEXT := entry.Text
					properties := map[string]string{}
					for _, v := range TEXT {
						kv := strings.Split(v, "=")
						if len(kv) == 2 {
							properties[kv[0]] = kv[1]
						}
					}

					var macAddrs []string
					val, ok := properties["mac_addr"]
					if !ok || val == "" {
						//No MacAddr found. Target node version too old
						macAddrs = []string{}
					} else {
						macAddrs = strings.Split(properties["mac_addr"], ",")
					}

					//log.Println(properties)
					discoveredHost = appendUniqueHost(discoveredHost, &NetworkHost{
						HostName:     entry.HostName,
						Port:         entry.Port,
						IPv4:         entry.AddrIPv4,
						Domain:       properties["domain"],
						Model:        properties["model"],
						UUID:         properties["uuid"],
						Vendor:       properties["vendor"],
						BuildVersion: properties["version_build"],
						MacAddr:      macAddrs,
						Online:       true,
					})

				}
			}

		}
	}(entries)

	//Resolve each of the mDNS and pipe it back to the log functions
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()
	err = resolver.Browse(ctx, "_http._tcp", "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	//Update the master scan record
	<-ctx.Done()
	return discoveredHost
}

// appendUniqueHost adds a host unless the same service (name, port, addresses, MAC) was already found.
// The resolver reports one answer per interface, which listed the same host several times.
func appendUniqueHost(list []*NetworkHost, h *NetworkHost) []*NetworkHost {
	key := func(n *NetworkHost) string {
		return fmt.Sprintf("%s|%d|%v|%v", n.HostName, n.Port, n.IPv4, n.MacAddr)
	}
	k := key(h)
	for _, e := range list {
		if key(e) == k {
			return list
		}
	}
	return append(list, h)
}

// Get all mac address of all interfaces
func getMacAddr() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}
