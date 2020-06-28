package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	//"github.com/labstack/gommon/log"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
)

var (
	//dataDir    = kingpin.Flag("data-dir", "Directory used for storage").Default("/Config/lib").String()
	//listenAddr = kingpin.Flag("listen-address", "Address to listen to").Default(":8080").String()
	//natEnabled            = kingpin.Flag("nat", "Whether NAT is enabled or not").Default("true").Bool()
	//natLink               = kingpin.Flag("nat-device", "Network interface to masquerade").Default("wlp2s0").String()
	//clientIPRange  = kingpin.Flag("client-ip-range", "Client IP CIDR").Default("10.0.0.0/8").String()
	//authUserHeader = kingpin.Flag("auth-user-header", "Header containing username").Default("X-Forwarded-User").String()
	//maxNumberClientConfig = kingpin.Flag("max-number-client-config", "Max number of configs an client can use. 0 is unlimited").Default("0").Int()
	tlsCertDir         = "."
	tlsKeyDir          = "."
	wgLiName           = "wg0"
	wgPort             = 51820
	//dataDir = "/Config/lib"
	//natLink               = kingpin.Flag("nat-device", "Network interface to masquerade").Default("ens3").String()
	dataDir = flag.String("data-dir", "/Config/lib", "Directory used for storage")
	listenAddr = flag.String("listen-address",":8080", "Address to listen to")
	natEnabled  = flag.Bool("nat", true, "Whether NAT is enabled or not")
	clientIPRange  = flag.String("client-ip-range","10.0.0.0/8", "Client IP CIDR")
	authUserHeader = flag.String("auth-user-header","X-Forwarded-User", "Header containing username")
	natLink = flag.String("nat-device","ens3", "Network interface to masquerade")

)

type contextKey string



type Server struct {
	serverConfPath string
	mutex          sync.RWMutex
	Config         *WgConf
	IPAddr         net.IP
	clientIPRange  *net.IPNet
	assets         http.Handler
}

type wgLink struct {
	attrs *netlink.LinkAttrs
}

func (w *wgLink) Attrs() *netlink.LinkAttrs {
	return w.attrs
}

func (w *wgLink) Type() string {
	return "wireguard"
}
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}
func NewServer() *Server {
	ipAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		log.Fatal("Error with those IPS:", err)
	}
	log.Println("IP Address: %s IP Network: %s", ipAddr, ipNet)
	err = os.Mkdir(*dataDir, 0700)
	if err != nil {
		log.Printf("Error init dir: ", err)
	}
	configPath := path.Join(*dataDir, "conf")
	log.Println(configPath)
	config := newServerConfig(configPath)

	assets := http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: ""})
	surf := Server{
		serverConfPath: configPath,
		mutex:          sync.RWMutex{},
		Config:         config,
		IPAddr:         ipAddr,
		clientIPRange:  ipNet,
		assets:         assets,
	}
	return &surf
}

func (serv *Server) UpInterface() error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "wg0"
	link := wgLink{attrs: &attrs}
	log.Printf("------------------------------------------")
	log.Println("Adding WireGuard device ", attrs.Name)
	err := netlink.LinkAdd(&link)
	if os.IsExist(err) {
		log.Printf("WireGuard interface %s already exists. REUSING. ", attrs.Name)
	} else if err != nil {
		log.Panic("Problem with the interface :::", err)
		return nil
	}
	log.Printf("------------------------------------------")
	log.Printf("Setting up IP address to wireguard device: ", serv.clientIPRange)
	addr, _ := netlink.ParseAddr("10.0.0.1/8")
	err = netlink.AddrAdd(&link, addr)
	if os.IsExist(err) {
		log.Printf("WireGuard interface %s already has the requested address: ", serv.clientIPRange)
	} else if err != nil {
		log.Panic(err)
		return err
	}
	log.Printf("------------------------------------------")
	log.Printf("Bringing up wireguard device: ", attrs.Name)
	err = netlink.LinkSetUp(&link)
	if err != nil {
		log.Panic("Couldn't bring up %s", attrs.Name)
	}

	return nil
}
func (serv *Server) allocateIP() net.IP {
	allocated := make(map[string]bool)
	allocated[serv.IPAddr.String()] = true

	for _, cfg := range serv.Config.Users {
		for _, dev := range cfg.Clients {
			allocated[dev.IP.String()] = true
		}
	}

	for ip := serv.IPAddr.Mask(serv.clientIPRange.Mask); serv.clientIPRange.Contains(ip); {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
		if !allocated[ip.String()] {
			log.Printf("Allocated IP: ", ip)
			return ip
		}
	}
	log.Fatal("Unable to allocate IP.Address range Exhausted")
	return nil
}
func (serv *Server) enableIPForward() error {
	p := "/proc/sys/net/ipv4/ip_forward"

	content, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}

	if string(content) == "0\n" {

		log.Printf("Enabling sys.net.ipv4.ip_forward - Success")

		return ioutil.WriteFile(p, []byte("1"), 0600)
	}

	return nil
}

func (serv *Server) wgConfiguation() error {
	log.Printf("------------------------------------------")
	log.Printf("Configuring WireGuard")
	wg, err := wgctrl.New()
	if err != nil {
		log.Panic("There is an error configuring WireGuard ::", err)
	}
	log.Printf("Adding PrivetKey....")
	keys, err := wgtypes.ParseKey(serv.Config.PrivateKey)
	if err != nil {
		log.Printf("Couldn't add PrivateKey ::", err)
	}
	log.Printf("PrivateKey->Successfully added -", serv.Config.PrivateKey)
	peers := make([]wgtypes.PeerConfig, 0)
	for user, cfg := range serv.Config.Users {
		for id, dev := range cfg.Clients {
			pbkey, err := wgtypes.ParseKey(dev.PublicKey)
			log.Printf("PublicKey TO client - Added")
			if err != nil {
				log.Printf("Couldn't add PublicKey to peer :: ", err)
			}
			AllowedIPs := make([]net.IPNet, 1)
			AllowedIPs[0] = *netlink.NewIPNet(dev.IP)
			peer := wgtypes.PeerConfig{
				PublicKey:         pbkey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        AllowedIPs,
			}
			log.Printf("Adding user ")
			log.Printf("User: %s, ClientID %s: , Publickey: %s AllowedIPS: %s", user, id, dev.PublicKey, peer.AllowedIPs)
			peers = append(peers, peer)
		}

	}
	//pers := time.Duration(21)
	//log.Info("adding ME")
	//ip := net.ParseIP("10.0.0.2/8")
	//peer_key, err := wgtypes.ParseKey("hY6dXQboU1KRwUZ/UGFecIw6JKN97/RO6wQDkWA0MXA=")
	//wgAllowedIPs := make([]net.IPNet,1)
	//wgAllowedIPs[0] = *netlink.NewIPNet(ip)
	//peerA := wgtypes.PeerConfig{
	//	PublicKey:         peer_key,
	//	ReplaceAllowedIPs: false,
	//	PersistentKeepaliveInterval: &pers,
	//
	//}
	//
	//peers = append(peers, peerA)
	//log.Info("successfuly added ME")
	cfg := wgtypes.Config{
		PrivateKey:   &keys,
		ListenPort:   &wgPort,
		ReplacePeers: true,
		Peers:        peers,
	}
	err = wg.ConfigureDevice("wg0", cfg)
	if err != nil {
		log.Fatal("Error configuring device ::", err)
		return err
	}
	return nil
}
//func (serv *Server) natConfigure() error{
//	log.Info("Adding NAT / IP masquerading using nftables")
//	ns, err := netns.Get()
//
//	conn := nftables.Conn{NetNS: int(ns)}
//
//	log.Info("Flushing nftable rulesets")
//	conn.FlushRuleset()
//
//	log.Info("Setting up nftable rules for ip masquerading")
//
//	nat := conn.AddTable(&nftables.Table{
//		Family: nftables.TableFamilyIPv4,
//		Name:   "nat",
//	})
//
//	conn.AddChain(&nftables.Chain{
//		Name:     "prerouting",
//		Table:    nat,
//		Type:     nftables.ChainTypeNAT,
//		Hooknum:  nftables.ChainHookPrerouting,
//		Priority: nftables.ChainPriorityFilter,
//	})
//
//	post := conn.AddChain(&nftables.Chain{
//		Name:     "postrouting",
//		Table:    nat,
//		Type:     nftables.ChainTypeNAT,
//		Hooknum:  nftables.ChainHookPostrouting,
//		Priority: nftables.ChainPriorityNATSource,
//	})
//
//	conn.AddRule(&nftables.Rule{
//		Table: nat,
//		Chain: post,
//		Exprs: []expr.Any{
//			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
//			&expr.Cmp{
//				Op:       expr.CmpOpEq,
//				Register: 1,
//				Data:     ifname(*natLink),
//			},
//			&expr.Masq{},
////		},
////	})
//log.Info("NAT Ready")
//	if err = conn.Flush(); err != nil {
//		return err
//	}
//	return nil
//}



func (serv *Server) reconfiguringWG() error {
	log.Printf("Reconfiguring wireGuard interface: wg0")

	err := serv.Config.Write()
	if err != nil {
		log.Fatal("Error Writing on configuration file ", err)

	}
	err = serv.wgConfiguation()
	if err != nil {
		log.Printf("Error Configuring file ::", err)
	}
	return nil
}
func (serv *Server) Start() error {

	err := serv.UpInterface()
	if err != nil {
		return err
	}
	log.Printf("------------------------------------------")
	log.Printf("Enabling IP Forward....")
	err = serv.enableIPForward()
	if err != nil {

		log.Printf("Couldnt enable IP Forwarding:  ", err)
	}
	err = serv.wgConfiguation()
	if err != nil {
		log.Panic("Couldnt Configure interface ::", err)
	}
	//err = serv.natConfigure()
	//if err != nil{
	//	log.Error("COuldnt configure NAT :: ", err)
	//}
	return nil

}

func main() {

	s := NewServer()

	s.Start()
	s.StartAPI()
}

func getTlsConfig() *tls.Config {
	caCertFile := filepath.Join(tlsCertDir, "ca.crt")
	certFile := filepath.Join(tlsCertDir, "server.crt")
	keyFile := filepath.Join(tlsKeyDir, "server.key")

	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	caCertPem, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}

	trustedCaPool := x509.NewCertPool()
	if !trustedCaPool.AppendCertsFromPEM(caCertPem) {
	}

	return &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    trustedCaPool,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	}
}
