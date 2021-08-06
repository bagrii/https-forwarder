package forwarder

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"time"

	"gopkg.in/ini.v1"

	"onethinglab.com/logger"
)

var (
	InfoLogger = logger.InfoLogger
	ErrorLogger = logger.ErrorLogger
	WarningLogger = logger.WarningLogger
)

// ForwardApplication described all components needed to forward request to.
type ForwardApplication struct {
	// User friendly name of the application.
	Name string `ini:"Name"`
	// Fully qualified domain name (FQDN) of a host that receives requests from outside.
	// That the name specified in HTTPS certificate.
	UpstreamHost string `ini:"UpstreamHost"`
	// Fully qualified domain name (FQDN) of a host that will receive request sent to `UpstreamHost`,
	// usually localhost.
	DownstreamHost string `ini:"DownstreamHost"`
	// Public key that contains PEM encoded data.
	CertFile string `ini:"CertFile"`
	// Private key that contains PEM encoded data.
	KeyFile string `ini:"KeyFile"`
}

// LoadApplications read list of application from `cfgfile` ini file and returns mapping
// of upstream host name to application description.
func LoadApplications(filename string) (map[string]ForwardApplication, error) {
	file, err := ini.Load(filename)
	if err != nil {
		return nil, err
	}

	var apps map[string]ForwardApplication = make(map[string]ForwardApplication)
	for _, section := range file.Sections() {
		if section.Name() == ini.DefaultSection {
			continue
		}
		var app ForwardApplication
		t, v := reflect.TypeOf(app), reflect.ValueOf(&app).Elem()
		for i := 0; i < t.NumField(); i++ {
			if name := t.Field(i).Tag.Get("ini"); len(name) > 0 {
				key, err := section.GetKey(name)
				if err != nil {
					return nil, err
				}

				field := v.FieldByName(t.Field(i).Name)
				field.SetString(key.Value())
			}
		}
		apps[app.UpstreamHost] = app
	}

	return apps, nil
}

// Forward waits for incoming requests on `port` and redirect them to particular application registered in `apps`.
// HTTP is redirected to HTTPS automatically.
func Forward(port string, apps map[string]ForwardApplication) {
	fileExists := func(filename string) bool {
		if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
			return false
		}
		return true
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if app, ok := apps[r.Host]; ok {
			target, err := url.Parse(app.DownstreamHost)
			if err != nil {
				ErrorLogger.Printf("Cannot parse downstream host: %s due to error: %s\n",
					app.DownstreamHost, err)
				http.Error(w, "Request cannot be proceed.", http.StatusServiceUnavailable) 
				return
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			d := proxy.Director
			remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ErrorLogger.Printf("Cannot split host and port for %s due to error: %s\n",
					r.RemoteAddr, err)
				// just pass it over to downstream application.
				remoteAddr = r.RemoteAddr
			}
			proxy.Director = func(r *http.Request) {
				d(r)
				r.Header.Add("X-Real-IP", remoteAddr)
			}
			InfoLogger.Printf("Forward request %s -> %s\n", r.Host, app.DownstreamHost)

			proxy.ServeHTTP(w, r)
		} else {
			WarningLogger.Printf("No application is registered for host: %s\n", r.Host)
			http.Error(w, "Request cannot be proceed.", http.StatusBadGateway)
			return
		}
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
    tlsConfig.Certificates = []tls.Certificate{}
NextApp:
	for _, app := range apps {
		for _, filename := range []string{app.CertFile, app.KeyFile} {
			if !fileExists(filename) {
				ErrorLogger.Printf("File %s is not exist, skipping %s ...\n", filename, app.Name)
				continue NextApp
			}
		}
		if cert, err := tls.LoadX509KeyPair(app.CertFile, app.KeyFile); err == nil {
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		} else {
			ErrorLogger.Printf("Cannot load key pair for %s: %s/%s due to error: %s\n",
				app.Name, app.CertFile, app.KeyFile, err)
			continue
		}
	}
	http.HandleFunc("/", handler)
	listener, err := tls.Listen("tcp", port, tlsConfig)
	if err != nil {
		ErrorLogger.Printf("Cannot create TCP listener due to error: %s\n", err)
		return
	}

	redirecHTTP2HTTPS()

	server := &http.Server{
        ReadTimeout:    15 * time.Second,
        WriteTimeout:   10 * time.Second,
		IdleTimeout:  120 * time.Second,
        MaxHeaderBytes: 1 << 20,
        TLSConfig:      tlsConfig,
    }
	InfoLogger.Println("Listening...")
	ErrorLogger.Fatal(server.Serve(listener))
}

func redirecHTTP2HTTPS() {
	redirect := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Connection", "close")
		target := "https://" + req.Host + req.URL.String()

		InfoLogger.Printf("redirect HTTP to HTTPS traffic %s\n", target)

		http.Redirect(w, req, target, http.StatusMovedPermanently)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", redirect)
	go http.ListenAndServe(":80", mux)
}
