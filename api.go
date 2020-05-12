package main

import (
	"context"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/gommon/log"
	"net/http"
	"strconv"
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
			ip := serv.allocateIP()
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
	router.GET("/WG/API/getclient", serv.GetClients)


	return http.ListenAndServe(*listenAddr, serv.userFromHeader(router))

}