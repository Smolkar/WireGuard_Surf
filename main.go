package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/gommon/log"
	"github.com/vishvananda/netlink"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"net/http"
	//"net/http/httputil"
	"os"
	"path"
	"path/filepath"
	"sync"
	//"time"
)

var (
	dataDir = kingpin.Flag("data-dir", "Directory used for storage").Default("/Config/lib").String()
	listenAddr            = kingpin.Flag("listen-address", "Address to listen to").Default(":8080").String()
	//natEnabled            = kingpin.Flag("nat", "Whether NAT is enabled or not").Default("true").Bool()
	//natLink               = kingpin.Flag("nat-device", "Network interface to masquerade").Default("wlp2s0").String()
	clientIPRange         = kingpin.Flag("client-ip-range", "Client IP CIDR").Default("172.31.255.0/24").String()
	authUserHeader        = kingpin.Flag("auth-user-header", "Header containing username").Default("X-Forwarded-User").String()
	//maxNumberClientConfig = kingpin.Flag("max-number-client-config", "Max number of configs an client can use. 0 is unlimited").Default("0").Int()
	//
	wgLinkName   = kingpin.Flag("wg-device-name", "WireGuard network device name").Default("wg1		").String()
	//wgListenPort = kingpin.Flag("wg-listen-port", "WireGuard UDP port to listen to").Default("51820").Int()
	//wgEndpoint   = kingpin.Flag("wg-endpoint", "WireGuard endpoint address").Default("127.0.0.1:51820").String()
	//wgAllowedIPs = kingpin.Flag("wg-allowed-ips", "WireGuard client allowed ips").Default("0.0.0.0/0").Strings()
	//wgDNS        = kingpin.Flag("wg-dns", "WireGuard client DNS server (optional)").Default("").String()
	tlsCertDir = "."
	tlsKeyDir  = "."
	wgLiName = "wg0"



)
type contextKey string

const key = contextKey("user")

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
	ipAddr, ipNet, err := net.ParseCIDR("10.0.10.0/8")
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

func (serv *Server) UpInterface() error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "wg-Real"
	link := wgLink{attrs: &attrs}
	fmt.Println(*wgLinkName)
	log.Info("Adding WireGuard device ", attrs.Name)
	err := netlink.LinkAdd(&link)
	if os.IsExist(err){
		log.Info("WireGuard interface %s already exists. REUSING. ", attrs.Name)
	} else if err != nil{
		log.Error("Problem with the interface :::",err)
		return nil
	}

	log.Debug("Setting up IP address to wireguard device: ", serv.clientIPRange)
	addr, _ := netlink.ParseAddr("10.0.10.0/8")
	err = netlink.AddrAdd(&link, addr)
	if os.IsExist(err){
		log.Info("WireGuard inteface %s already has the requested address: ", serv.clientIPRange)
	}else if err != nil{
		log.Error(err)
		return err
	}

	log.Info("Bringing up wireguard device: ", attrs.Name)
	err = netlink.LinkSetUp(&link)
	if err != nil{
		log.Error("Couldn't bring up %s", attrs.Name)
	}
	return nil
}

func (serv *Server) WhoAmI(w http.ResponseWriter, r *http.Request, _ httprouter.Param)  {
	user :=  r.Context().Value(key).(string)
	log.Info(user)
	err := json.NewEncoder(w).Encode(struct{User string}{user})
	if err != nil {
		log.Error(err)
	}
	w.WriteHeader(http.StatusInternalServerError)

}

func (s *Server) enableIPForward() error {
	p := "/proc/sys/net/ipv4/ip_forward"

	content, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}

	if string(content) == "0\n" {
		log.Info("Enabling sys.net.ipv4.ip_forward")
		return ioutil.WriteFile(p, []byte("1"), 0600)
	}

	return nil
}
func (serv *Server) Start() error{

	err := serv.UpInterface()
	if err != nil{
		return err
	}

	router := httprouter.New()

		//router.GET("/api")
	return http.ListenAndServe(*listenAddr,serv.userFromHeader(router))
}
func (serv *Server) userFromHeader(handler http.Handler) http.Handler{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		user := r.Header.Get(*authUserHeader)
		if user == "" {
			log.Debug("Unauth request")
			user = "anonymnouys"
		}
		cookie := http.Cookie{
			Name:       "wgUser",
			Value:      user,
			Path:       "/",
		}
		http.SetCookie(w,&cookie)
		ctx := context.WithValue(r.Context(),key, user)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

}
//user := r.Context().Value(key).(string)
//usercfg := serv.Config.Users[user]
//if usercfg == nil{
//	w.WriteHeader(http.StatusNotFound)
//	return
//}
func (serv *Server) Index(w http.ResponseWriter, r *http.Request, ps httprouter.Params){
	log.Debug("Serving single page app from URL", r.URL)
	r.URL.Path = "/"
	serv.assets.ServeHTTP(w,r)
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