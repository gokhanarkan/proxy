# CORS Proxy Server

## Overview

This project is a lightweight HTTP proxy server designed to handle Cross-Origin Resource Sharing (CORS) requests while offering rate-limiting, security, and timeout management. It is suitable for use cases where clients need to access external resources with CORS policies, and offers additional protections such as rate-limiting by IP, restricted access to private IP ranges, and prevention of certain HTTP methods.

## Features

- **CORS Support**: Automatically handles preflight CORS requests and sets appropriate headers.
- **Rate Limiting**: Limits requests to 60 per minute per IP address to prevent abuse.
- **Timeouts**: Enforces request and response timeouts to prevent hanging requests.
- **Security**: Prevents access to private or loopback IP addresses, disallows unsafe HTTP methods (e.g., `CONNECT`, `TRACE`, `TRACK`), and sanitizes user-provided URLs.
- **Custom HTTP Client**: Configured with custom timeouts and connection pooling to optimize performance and safety.

## Installation

### Prerequisites

- Go 1.16 or higher

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/cors-proxy.git
   cd cors-proxy
   ```

2. Build the binary:
   ```bash
   go build -o cors-proxy
   ```

3. Run the server:
   ```bash
   ./cors-proxy
   ```

The server will start on port 8080 by default.

## Usage

### Proxying Requests

Send a GET or POST request to the proxy server with the target URL in the `url` query parameter:

```bash
curl -X GET 'http://localhost:8080/?url=https://example.com'
```

### CORS Preflight Request

For preflight requests (using the `OPTIONS` method), the server will respond with the necessary CORS headers.

### Rate Limiting

The server allows up to 60 requests per minute from a single IP address. If the limit is exceeded, the client will receive a `429 Too Many Requests` response.

## Configuration

The following constants can be modified in the source code to change the behavior of the proxy:

- `requestsPerMinute`: The number of allowed requests per minute per IP address.
- `maxBodySize`: The maximum size of the request or response body (default: 10 MB).
- `requestTimeout`: Timeout for each request (default: 30 seconds).
- `idleConnTimeout`: Timeout for idle connections (default: 90 seconds).
- `responseHeaderTimeout`: Timeout for receiving the response headers (default: 10 seconds).

## Security Considerations

- **Disallowed Methods**: The server rejects `CONNECT`, `TRACE`, and `TRACK` methods to avoid potential abuse.
- **Private IP Protection**: Requests to private IP ranges (e.g., `192.168.x.x`, `127.x.x.x`) are blocked for security.
- **CORS Headers**: The server automatically adds CORS headers to all responses and handles `OPTIONS` preflight requests.

## Graceful Shutdown

The server gracefully shuts down on receiving interrupt signals (`SIGINT`, `SIGTERM`), allowing ongoing requests to complete before terminating.

## Logging

The server logs all requests, including the client IP and target URL, as well as any errors that occur during request handling.

## License

This project is licensed under the MIT License.

---

This is a basic CORS proxy server. Make sure to evaluate and adjust its security configurations based on your use case before deploying it in a production environment.
