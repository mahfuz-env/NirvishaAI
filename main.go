package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"nirvishaai/backend/config"
	"nirvishaai/backend/handlers"
	"nirvishaai/backend/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	config.Load()

	if err := store.InitRedis(); err != nil {
		log.Printf("WARNING: Redis connection failed: %v", err)
		log.Printf("Server will start but scan/verify features will not work until Redis is available")
	}
	defer store.Close()

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   strings.Split(config.App.AllowedOrigins, ","),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","service":"nirvishaai"}`))
	})

	r.Route("/api", func(r chi.Router) {
		r.Route("/verify", func(r chi.Router) {
			r.Post("/dns", handlers.StartDNSVerification)
			r.Post("/file", handlers.CheckFileVerification)
			r.Get("/status", handlers.GetVerificationStatus)
		})

		r.Route("/scan", func(r chi.Router) {
			r.Post("/start", handlers.StartScan)
			r.Get("/status/{id}", handlers.GetScanStatus)
			r.Get("/result/{id}", handlers.GetScanResult)
		})

		r.Route("/report", func(r chi.Router) {
			r.Get("/pdf/{id}", handlers.GeneratePDF)
			r.Get("/md/{id}", handlers.GenerateMD)
		})
	})

	addr := fmt.Sprintf(":%s", config.App.Port)
	log.Printf("NirvishaAI backend running on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
