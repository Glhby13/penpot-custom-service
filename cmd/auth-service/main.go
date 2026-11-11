// Command auth-service signs users in to Penpot with their AD account: the Penpot login form posts to this service,
// which checks the password and the access role with Keycloak (direct grant, no redirect) and then obtains the
// Penpot session from Penpot itself.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitlab.devops.btn.co.id/platform/penpot-custom-service/internal/authservice"
)

const serviceName = "auth-service"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	cfg, err := authservice.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"ERROR","service":%q,"msg":"config error","error":%q}`+"\n", serviceName, err.Error())
		os.Exit(1)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(cfg.LogLevel))); err != nil {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("service", serviceName)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           authservice.NewServer(cfg, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No read/write timeout: this service also carries Penpot's uploads, event streams and WebSockets.
		IdleTimeout: 120 * time.Second,
	}
	go func() {
		log.Info("starting", "port", cfg.Port, "keycloak", cfg.KeycloakURL, "penpot", cfg.PenpotBackendURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info("stopped")
}

// healthcheck is the container HEALTHCHECK: the image has no shell or curl.
func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/healthz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
