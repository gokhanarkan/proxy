package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Rate limiting settings
	requestsPerMinute = 60
	cleanupInterval   = time.Minute

	// Timeouts and limits
	requestTimeout        = 30 * time.Second
	maxBodySize           = 10 * 1024 * 1024 // 10 MB
	idleConnTimeout       = 90 * time.Second
	responseHeaderTimeout = 10 * time.Second
)

// RateLimiter implements a token bucket rate limiter per IP
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.Mutex
}

// Visitor holds the last time and count for a visitor
type Visitor struct {
	remaining int
	resetTime time.Time
}

// NewRateLimiter initialises a new RateLimiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
	}
	go rl.cleanup()
	return rl
}

// Allow checks if a request from an IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	visitor, exists := rl.visitors[ip]
	if !exists || now.After(visitor.resetTime) {
		rl.visitors[ip] = &Visitor{
			remaining: requestsPerMinute - 1,
			resetTime: now.Add(time.Minute),
		}
		return true
	}

	if visitor.remaining > 0 {
		visitor.remaining--
		return true
	}

	return false
}

// cleanup removes expired entries from the visitors map
func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(cleanupInterval)
		rl.mu.Lock()
		now := time.Now()
		for ip, visitor := range rl.visitors {
			if now.After(visitor.resetTime) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func main() {
	rateLimiter := NewRateLimiter()

	// Custom HTTP client with timeouts and connection pooling
	httpClient := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       idleConnTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			DisableCompression:    false, // Enable compression for performance
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent redirects
			return http.ErrUseLastResponse
		},
	}

	// Create a new server mux
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Limit the size of the request body
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		defer r.Body.Close()

		// Disallow certain HTTP methods
		disallowedMethods := []string{"CONNECT", "TRACE", "TRACK"}
		for _, method := range disallowedMethods {
			if r.Method == method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}

		// Extract client IP address
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Error parsing client IP: %v", err)
			http.Error(w, "Unable to parse client IP", http.StatusInternalServerError)
			return
		}

		// Apply rate limiting
		if !rateLimiter.Allow(clientIP) {
			log.Printf("Rate limit exceeded for IP: %s", clientIP)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Handle CORS preflight requests
		if r.Method == http.MethodOptions {
			addCORSHeaders(w, r)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Get the target URL from the 'url' query parameter
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, "'url' query parameter is missing", http.StatusBadRequest)
			return
		}

		// Parse and validate the target URL
		parsedURL, err := url.Parse(targetURL)
		if err != nil || !isValidURL(parsedURL) {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		// Prevent access to private or loopback addresses
		if isPrivateIP(parsedURL.Hostname()) {
			http.Error(w, "Access to private IP ranges is prohibited", http.StatusForbidden)
			return
		}

		// Log the incoming request
		log.Printf("Received request from %s for %s", clientIP, parsedURL.Redacted())

		// Create a new request to the target URL
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, r.Method, parsedURL.String(), r.Body)
		if err != nil {
			log.Printf("Failed to create request to target URL %s: %v", parsedURL.String(), err)
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		// Copy headers, excluding hop-by-hop headers
		copyHeaders(req.Header, r.Header)
		req.Header.Del("Host")

		// Perform the request
		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("Failed to reach target server %s: %v", parsedURL.String(), err)
			http.Error(w, "Failed to reach the target server", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Limit the size of the response body
		resp.Body = http.MaxBytesReader(w, resp.Body, maxBodySize)

		// Copy response headers and status code
		copyHeaders(w.Header(), resp.Header)
		addCORSHeaders(w, r)
		w.WriteHeader(resp.StatusCode)

		// Copy the response body
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("Error copying response body: %v", err)
			// Cannot send error to client at this point
		}
	})

	// Wrap the mux with a timeout handler
	handlerWithTimeout := http.TimeoutHandler(mux, requestTimeout, "Service Unavailable")

	// Create an HTTP server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      handlerWithTimeout,
		ReadTimeout:  requestTimeout,
		WriteTimeout: requestTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Println("CORS Proxy Server is running on port 8080")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe error: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Create a deadline to wait for current operations to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

// addCORSHeaders adds necessary CORS headers to the response
func addCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

	if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
		w.Header().Set("Access-Control-Allow-Headers", requestHeaders)
	} else {
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	}

	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// isValidURL validates the URL scheme and ensures it's HTTP or HTTPS
func isValidURL(u *url.URL) bool {
	return u.Scheme == "http" || u.Scheme == "https"
}

// isPrivateIP checks if the given hostname resolves to a private or loopback IP
func isPrivateIP(hostname string) bool {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		log.Printf("DNS lookup error for hostname %s: %v", hostname, err)
		return true
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
	}

	return false
}

// copyHeaders copies headers from src to dst, excluding hop-by-hop headers
func copyHeaders(dst, src http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Expect", // Added Expect to the list
	}

	for k, vv := range src {
		// Skip hop-by-hop headers
		skip := false
		for _, h := range hopByHopHeaders {
			if strings.EqualFold(k, h) {
				skip = true
				break
			}
		}
		if !skip {
			dst[k] = vv
		}
	}
}
