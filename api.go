package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/gommon/log"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"github.com/skip2/go-qrcode"
)

var (
	//clientIPRange  = kingpin.Flag("client-ip-range", "Client IP CIDR").Default("10.10.10.0/8").String()
	//authUserHeader = kingpin.Flag("auth-user-header", "Header containing username").Default("X-Forwarded-User").String()
	//maxNumberClientConfig = kingpin.Flag("max-number-client-config", "Max number of configs an client can use. 0 is unlimited").Default("0").Int()
	wgLinkName   = kingpin.Flag("wg-device-name", "WireGuard network device name").Default("wg0").String()
	wgListenPort = kingpin.Flag("wg-listen-port", "WireGuard UDP port to listen to").Default("51820").Int()
	wgEndpoint   = kingpin.Flag("wg-endpoint", "WireGuard endpoint address").Default("127.0.0.1:51820").String()
	wgAllowedIPs = kingpin.Flag("wg-allowed-ips", "WireGuard client allowed ips").Default("0.0.0.0/0").Strings()
	wgDNS        = kingpin.Flag("wg-dns", "WireGuard client DNS server (optional)").Default("").String()

	filenameRe = regexp.MustCompile("[^a-zA-Z0-9]+")
	)
const key = contextKey("user")

func (serv *Server) userFromHeader(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get(*authUserHeader)
		if user == "" {
			log.Debug("Unauthenticated request")
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
	log.Debug("Serving single page app from URL", r.URL)
	r.URL.Path = "/"
	serv.assets.ServeHTTP(w, r)
}
func (serv *Server) Idetify(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var user = r.Context().Value(key).(string)
	log.Info(user)
	err := json.NewEncoder(w).Encode(struct{ User string }{user})
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func (s *Server) GetClients(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.Info("Getting Clients")
	user := r.Context().Value(key).(string)
	log.Debug(user)
	clients := map[string]*ClientConfig{}
	userConfig := s.Config.Users[user]
	if userConfig != nil {
		clients = userConfig.Clients
	}

	err := json.NewEncoder(w).Encode(clients)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *Server) GetClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := r.Context().Value(key).(string)
	usercfg := s.Config.Users[user]
	if usercfg == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	client := usercfg.Clients[ps.ByName("client")]
	if client == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

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

	format := r.URL.Query().Get("format")

	if format == "qrcode" {
		png, err := qrcode.Encode(configData, qrcode.Medium, 220)
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(png)
		if err != nil {
			log.Error(err)
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
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (serv *Server) CreateClient(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serv.mutex.Lock()
	defer serv.mutex.Unlock()

	user := r.Context().Value(key).(string)

	log.Info("Creating client :: User %s ", user)
	cli := serv.Config.GetUSerConfig(user)
	log.Info("User Config: %#v", cli)

	if maxNumberCliConfig > 0 {
		if len(cli.Clients) >= maxNumberCliConfig {
			log.Errorf("there too many configs %q", cli.Name)
			e := struct {
				Error string
			}{
				Error: "Max number of configs: " + strconv.Itoa(maxNumberCliConfig),
			}
			w.WriteHeader(http.StatusBadRequest)
			err := json.NewEncoder(w).Encode(e)
			if err != nil {
				log.Errorf("There was an API ERRROR - CREATE CLIENT ::", err)
				w.WriteHeader(http.StatusBadRequest)
				err := json.NewEncoder(w).Encode(e)
				if err != nil {
					log.Errorf("Error enocoding ::", err)
					return
				}
				return
			}
			decoder := json.NewDecoder(r.Body)
			client := &ClientConfig{}
			err = decoder.Decode(&client)
			if err != nil {
				log.Warn(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if client.Name == "" {
				log.Info("No CLIENT NAME found.....USING DEFAULT...\"unnamed Client\"")
				client.Name = "Unnamed Client"
			}
			i := 0
			for k := range cli.Clients {
				n, err := strconv.Atoi(k)
				if err != nil {
					log.Errorf("THere was an error strc CONV :: ", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if n > i {
					i = n
				}
			}
			i += 1
			log.Info("Allocating IP")
			ip := serv.allocateIP()
			log.Info("Creating Client Config")
			client = NewClientConfig(ip, client.Name, client.Info)
			cli.Clients[strconv.Itoa(i)] = client
			err = serv.reconfiguringWG()
			if err != nil{
				log.Info("error Reconfiguring :: ", err)
			}
			err = json.NewEncoder(w).Encode(client)
			if err != nil {
				log.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}
func (serv *Server) StartAPI() error {

	router := httprouter.New()
	router.GET("/WG/API/index", serv.Index)
	router.GET("/WG/API/whoami", serv.Idetify)
	router.POST("/WG/API/createclient", serv.CreateClient)
	router.GET("/WG/API/getclients", serv.GetClients)
	router.GET("/WG/API/getclient", serv.GetClient)


	return http.ListenAndServe(*listenAddr, serv.userFromHeader(router))

}