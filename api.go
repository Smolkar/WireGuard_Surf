	package main


	import (
		"context"
		"encoding/json"
		"flag"
		"fmt"
		"github.com/julienschmidt/httprouter"
		"github.com/skip2/go-qrcode"
		"log"
		"net/http"
		"regexp"
		"strconv"
		"gopkg.in/alecthomas/kingpin.v2"
		"strings"

	)


var (
	//clientIPRange  = kingpin.Flag("client-ip-range", "Client IP CIDR").Default("10.10.10.0/8").String()
	//authUserHeader = kingpin.Flag("auth-user-header", "Header containing username").Default("X-Forwarded-User").String()
	//maxNumberClientConfig = kingpin.Flag("max-number-client-config", "Max number of configs an client can use. 0 is unlimited").Default("0").Int()
	//wgLinkName   = kingpin.Flag("wg-device-name", "WireGuard network device name").Default("wg0").String()
	//wgListenPort = kingpin.Flag("wg-listen-port", "WireGuard UDP port to listen to").Default("51820").Int()
	//wgEndpoint   = kingpin.Flag("wg-endpoint", "WireGuard endpoint address").Default("127.0.0.1:51820").String()
	wgAllowedIPs = kingpin.Flag("wg-allowed-ips", "WireGuard client allowed ips").Default("0.0.0.0/0").Strings()
	//wgDNS        = kingpin.Flag("wg-dns", "WireGuard client DNS server (optional)").Default("").String()

	maxNumberCliConfig = 10
	filenameRe = regexp.MustCompile("[^a-zA-Z0-9]+")
	wgLinkName   = flag.String("wg-device-name","wg0", "WireGuard network device name")
	wgListenPort = flag.Int("wg-listen-port",51820, "WireGuard UDP port to listen to")
	wgEndpoint   = flag.String("wg-endpoint","127.0.0.1:51820", "WireGuard endpoint address")
	//wgAllowedIPs = flag.String("wg-allowed-ips","0.0.0.0/0", "WireGuard client allowed ips")
	wgDNS        = flag.String("wg-dns","8.8.8.8", "WireGuard client DNS server (optional)")


)
const key = contextKey("user")

func (serv *Server) userFromHeader(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get(*authUserHeader)
		if user == "" {
			log.Println("Unauthenticated request")
			user = "anonymous"

		}
		cookie := http.Cookie{
			Name:  "wguser",
			Value: user,
			Path:  "/",
		}
		http.SetCookie(w, &cookie)

		ctx := context.WithValue(r.Context(), key, user)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (serv *Server) Index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.Println("Serving single page app from URL", r.URL)
	r.URL.Path = "/"
	serv.assets.ServeHTTP(w, r)
}
func (serv *Server) Idetify(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var user = r.Context().Value(key).(string)
	log.Println(user)
	err := json.NewEncoder(w).Encode(struct{ User string }{user})
	if err != nil {
		log.Panic(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func (s *Server) GetClients(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.Println("Getting Clients")
	user := r.Context().Value(key).(string)
	log.Println(user)

	clients := map[string]*ClientConfig{}
	userConfig := s.Config.Users[user]
	if userConfig != nil {
		clients = userConfig.Clients
	}else{
		log.Println("This User have no clients")
	}

	err := json.NewEncoder(w).Encode(clients)
	if err != nil {
		log.Panic(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *Server) GetClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := r.Context().Value(key).(string)
	log.Println("Get One client")
	usercfg := s.Config.Users[user]
	if usercfg == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	log.Println("Client :::")
	client := usercfg.Clients[ps.ByName("client")]
	if client == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	log.Println("AllowedIP's COnfig")
	allowedIPs := strings.Join(*wgAllowedIPs, ",")

	dns := ""
	if *wgDNS != "" {
		dns = fmt.Sprint("DNS = ", *wgDNS)
	}

	configData := fmt.Sprintf(`[Interface]
%s
Address = %s
PrivateKey = %s
[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s
`, dns, client.IP.String(), client.PrivateKey, s.Config.PublicKey, allowedIPs, *wgEndpoint)
	log.Println(configData)
	format := r.URL.Query().Get("format")

	if format == "qrcode" {
		png, err := qrcode.Encode(configData, qrcode.Medium, 220)
		if err != nil {
			log.Panic(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(png)
		if err != nil {
			log.Panic(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		return
	}

	if format == "config" {
		filename := fmt.Sprintf("%s.conf", filenameRe.ReplaceAllString(client.Name, "_"))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.Header().Set("Content-Type", "application/config")
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprint(w, configData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	err := json.NewEncoder(w).Encode(client)
	if err != nil {
		log.Panic(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (serv *Server) CreateClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serv.mutex.Lock()
	defer serv.mutex.Unlock()

	user := r.Context().Value(key).(string)

	log.Printf("Creating client :: User ", user)
	cli := serv.Config.GetUSerConfig(user)
	log.Printf("User Config: ", cli.Clients, " ", cli.Name)

	if maxNumberCliConfig > 0 {
		if len(cli.Clients) >= maxNumberCliConfig {
			log.Panicf("there too many configs ", cli.Name)
			e := struct {
				Error string
			}{
				Error: "Max number of configs: " + strconv.Itoa(maxNumberCliConfig),
			}
			w.WriteHeader(http.StatusBadRequest)
			err := json.NewEncoder(w).Encode(e)
			if err != nil {
				log.Panicf("There was an API ERRROR - CREATE CLIENT ::", err)
				w.WriteHeader(http.StatusBadRequest)
				err := json.NewEncoder(w).Encode(e)
				if err != nil {
					log.Panicf("Error enocoding ::", err)
					return
				}
				return
			}
			decoder := json.NewDecoder(r.Body)
			client := &ClientConfig{}
			err = decoder.Decode(&client)
			if err != nil {
				log.Panic(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if client.Name == "" {
				log.Println("No CLIENT NAME found.....USING DEFAULT...\"unnamed Client\"")
				client.Name = "Unnamed Client"
			}
			i := 0
			for k := range cli.Clients {
				n, err := strconv.Atoi(k)
				if err != nil {
					log.Panicf("THere was an error strc CONV :: ", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if n > i {
					i = n
				}
			}
			i += 1
			log.Println("Allocating IP")
			ip := serv.allocateIP()
			log.Println("Creating Client Config")
			client = NewClientConfig(ip, client.Name, client.Info)
			cli.Clients[strconv.Itoa(i)] = client
			err = serv.reconfiguringWG()
			if err != nil{
				log.Println("error Reconfiguring :: ", err)
			}
			err = json.NewEncoder(w).Encode(client)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}
	func (s *Server) withAuth(handler httprouter.Handle) httprouter.Handle {
		return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			log.Println("Auth required")

			user := r.Context().Value(key)
			if user == nil {
				log.Panic("Error getting username from request context")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if user != ps.ByName("user") {
				log.Println("user ",user, " path: ", r.URL.Path, " Unauthorized access")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			handler(w, r, ps)
		}
	}

func (serv *Server) StartAPI() error {

	router := httprouter.New()
	router.GET("/index", serv.Index)
	router.GET("/whoami", serv.Idetify)
	router.POST("/WG/API/createclient/:user/clients", serv.withAuth(serv.CreateClient))
	router.GET("/WG/API/getclients/:user/clients",serv.withAuth(serv.GetClients))
	router.GET("/WG/API/getclient/:user/clients/:client", serv.withAuth(serv.GetClient))


	return http.ListenAndServe(*listenAddr, serv.userFromHeader(router))

}