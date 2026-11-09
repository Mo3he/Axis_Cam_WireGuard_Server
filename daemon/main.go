// Command WireGuard_Serverd is the WireGuard server supervised by the ACAP entry
// binary (app/main.c). Parameters arrive as ACAP_<PARAMETER> environment
// variables; the entry binary restarts this process when they change.
//
// It runs whether or not the server is enabled, so the settings page can always
// read the server public key and status. Configuration errors are reported in
// the status rather than by exiting, to avoid a restart loop.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

const (
	// statusAddr must be unique per device and match the "status" reverseProxy
	// target in manifest.json; see PARAM_CGI_FALLBACK.md in the portfolio repo.
	statusAddr = "127.0.0.1:2212"
	dataDir    = "localdata"

	// memoryLimit is a soft limit that makes the runtime collect and return
	// memory to the camera sooner after a traffic burst.
	memoryLimit = 64 << 20
)

func main() {
	log.SetFlags(0)
	debug.SetMemoryLimit(memoryLimit)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	s := &server{state: "disabled", connected: map[[32]byte]bool{}}

	addr := statusAddr
	if v := os.Getenv("WGS_STATUS_ADDR"); v != "" {
		addr = v
	}
	if ln, err := s.serveStatus(addr); err != nil {
		log.Printf("status API cannot bind %s: %v", addr, err)
	} else {
		defer ln.Close()
	}

	cfg, cfgErr := loadConfigFromEnv()
	s.cfg = cfg
	for _, problem := range cfg.PeerErrors {
		log.Printf("skipping %s", problem)
	}

	priv, generated, err := loadPrivateKey(cfg.PrivateKey, dataDir)
	if err != nil {
		s.setError(err)
	} else {
		if generated {
			log.Print("generated a new server key")
		}
		if pub, err := publicKey(priv); err != nil {
			s.setError(err)
		} else {
			s.pub, s.hasKey = pub, true
		}
	}

	switch {
	case !s.hasKey:
	case cfgErr != nil:
		s.setError(cfgErr)
	case !cfg.Enabled:
		log.Print("server disabled")
	default:
		if err := s.start(priv, nil, primaryIPv4, lanSubnet); err != nil {
			s.setError(err)
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop()
			log.Print("stopped")
			return
		case <-ticker.C:
			s.logHandshakes()
		}
	}
}
