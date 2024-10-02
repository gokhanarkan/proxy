package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Mock upstream server for testing
func startMockServer(handlerFunc http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handlerFunc))
}

// Test successful proxying of a GET request
func TestProxySuccess(t *testing.T) {
	// Start a mock upstream server
	upstream := startMockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})
	defer upstream.Close()

	// Start the proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the handler from the main code
		mainHandler(w, r)
	}))
	defer proxy.Close()

	// Make a request to the proxy
	proxyURL := proxy.URL + "/?url=" + url.QueryEscape(upstream.URL)
	req, err := http.NewRequest("GET", proxyURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(body) != "Hello, World!" {
		t.Errorf("Unexpected response body: %s", string(body))
	}

	// Check headers
	if resp.Header.Get("X-Test-Header") != "test-value" {
		t.Errorf("Missing or incorrect X-Test-Header")
	}

	// Check CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost" {
		t.Errorf("CORS header missing or incorrect")
	}
}

// Test handling of invalid URL
func TestProxyInvalidURL(t *testing.T) {
	// Start the proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mainHandler(w, r)
	}))
	defer proxy.Close()

	// Invalid URL
	proxyURL := proxy.URL + "/?url=ht!tp://invalid-url"

	resp, err := http.Get(proxyURL)
	if err != nil {
		t.Fatalf("Proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// Test blocking of private IP addresses
func TestProxyPrivateIP(t *testing.T) {
	// Start the proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mainHandler(w, r)
	}))
	defer proxy.Close()

	// Private IP URL
	proxyURL := proxy.URL + "/?url=http://127.0.0.1"

	resp, err := http.Get(proxyURL)
	if err != nil {
		t.Fatalf("Proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

// Test rate limiting
func TestProxyRateLimiting(t *testing.T) {
	// Start the proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mainHandler(w, r)
	}))
	defer proxy.Close()

	// Make requests exceeding the rate limit
	client := &http.Client{}
	for i := 0; i < requestsPerMinute+5; i++ {
		proxyURL := proxy.URL + "/?url=http://example.com"
		resp, err := client.Get(proxyURL)
		if err != nil {
			t.Fatalf("Proxy request failed: %v", err)
		}
		defer resp.Body.Close()

		if i < requestsPerMinute {
			if resp.StatusCode == http.StatusTooManyRequests {
				t.Errorf("Unexpected rate limit at request %d", i+1)
				break
			}
		} else {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Errorf("Expected rate limit at request %d", i+1)
				break
			}
		}

		// Sleep slightly to avoid overloading
		time.Sleep(10 * time.Millisecond)
	}
}

// Test handling of CORS preflight requests
func TestCORSPreflight(t *testing.T) {
	// Start the proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mainHandler(w, r)
	}))
	defer proxy.Close()

	// Preflight request
	req, err := http.NewRequest("OPTIONS", proxy.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Access-Control-Request-Method", "GET")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", resp.StatusCode)
	}

	// Check CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost" {
		t.Errorf("CORS header missing or incorrect")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("Access-Control-Allow-Methods header missing")
	}
}

// Helper function to wrap the main handler for testing
func mainHandler(w http.ResponseWriter, r *http.Request) {
	// Initialize the components as in main()
	rateLimiter := NewRateLimiter()
	// Custom HTTP client with timeouts and connection pooling
	httpClient := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       idleConnTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			DisableCompression:    false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Implement the handler logic here, similar to main()
	// Limit the size of the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer r.Body.Close()

	// Extract client IP address
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Unable to parse client IP", http.StatusInternalServerError)
		return
	}

	// Apply rate limiting
	if !rateLimiter.Allow(clientIP) {
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

	// Create a new request to the target URL
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, r.Method, parsedURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers, excluding hop-by-hop headers
	copyHeaders(req.Header, r.Header)
	req.Header.Del("Host")

	// Perform the request
	resp, err := httpClient.Do(req)
	if err != nil {
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
	io.Copy(w, resp.Body)
}
