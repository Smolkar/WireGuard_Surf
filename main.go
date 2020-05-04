package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/labstack/gommon/log"
	"github.com/vishvananda/netlink"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
)

var (
	dataDir = kingpin.Flag("data-dir", "Directory used for storage").Default("/Config/lib").String()
	//listenAddr            = kingpin.Flag("listen-address", "Address to listen to").Default(":8080").String()
	//natEnabled            = kingpin.Flag("nat", "Whether NAT is enabled or not").Default("true").Bool()
	//natLink               = kingpin.Flag("nat-device", "Network interface to masquerade").Default("wlp2s0").String()
	clientIPRange         = kingpin.Flag("client-ip-range", "Client IP CIDR").Default("172.31.255.0/24").String()
	//authUserHeader        = kingpin.Flag("auth-user-header", "Header containing username").Default("X-Forwarded-User").String()
	//maxNumberClientConfig = kingpin.Flag("max-number-client-config", "Max number of configs an client can use. 0 is unlimited").Default("0").Int()
	//
	wgLinkName   = kingpin.Flag("wg-device-name", "WireGuard network device name").Default("wg0").String()
	//wgListenPort = kingpin.Flag("wg-listen-port", "WireGuard UDP port to listen to").Default("51820").Int()
	//wgEndpoint   = kingpin.Flag("wg-endpoint", "WireGuard endpoint address").Default("127.0.0.1:51820").String()
	//wgAllowedIPs = kingpin.Flag("wg-allowed-ips", "WireGuard client allowed ips").Default("0.0.0.0/0").Strings()
	//wgDNS        = kingpin.Flag("wg-dns", "WireGuard client DNS server (optional)").Default("").String()
	tlsCertDir = "."
	tlsKeyDir  = "."



)
type Server struct{
	serverConfPath string
	mutex sync.RWMutex
	Config *WgConf
	IPAddr net.IP
	clientIPRange *net.IPNet
	assets http.Handler
}

type wgLink struct{
	attrs *netlink.LinkAttrs
}


func (w *wgLink) Attrs() *netlink.LinkAttrs {
	return w.attrs
}

func (w *wgLink) Type() string {
	return "wireguard"
}

func NewServer() *Server {
	ipAddr, ipNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil{
		log.Fatal("Error with those IPS:",err)
	}
	log.Info("IP Address: %s IP Network: %s", ipAddr, ipNet)
	err = os.Mkdir(*dataDir,0700)
	if err != nil{
		log.Debug(	"Error init dir: ", err)
	}
	configPath := path.Join(*dataDir, "conf")
	log.Debug(configPath, )
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
	fmt.Println(assets)
	return &surf
}

func (serv *Server) UpInterface() error{
	attrs := netlink.NewLinkAttrs()
	attrs.Name = *wgLinkName
	link := wgLink{attrs: &attrs}

	log.Debug("Adding WireGuard device %s", *wgLinkName)
	err := netlink.LinkAdd(&link)
	if os.IsExist(err){
		log.Info("WireGuard interface %s already exists. REUSING. ", *wgLinkName)
	} else if err != nil{
		return err
	}

	log.Debug("Setting up IP address to wireguard device: ", serv.clientIPRange)
	addr, _ := netlink.ParseAddr(*clientIPRange)
	err = netlink.AddrAdd(&link, addr)
	if os.IsExist(err){
		log.Info("WireGuard inteface %s already has the requested address: ", serv.clientIPRange)
	}

	log.Debug("Bringing up wireguard device: ", *wgLinkName)
	err = netlink.LinkSetUp(&link)
	if err != nil{
		log.Error("COuldn't bring up %s", *wgLinkName)
	}
	return err
}

func (serv *Server) Start() error{
err := serv.UpInterface()
if err != nil{

}
return  err
}


func main(){

	s := NewServer()
	fmt.Println("Complete")
	s.Start()
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