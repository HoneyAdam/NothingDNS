package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================================
// HTTP client helpers
// ============================================================================

func apiRequest(method, path, body string) (map[string]interface{}, error) {
	server := strings.TrimRight(globalFlags.Server, "/")
	// Reject scheme-less server URLs with a clear, actionable message.
	// Without this guard, `--server localhost:8080` is interpreted by
	// Go's net/url parser as scheme="localhost" rest="8080/api/...",
	// and the request fails with the cryptic
	//   `unsupported protocol scheme "localhost"`.
	// Most operators reach for `localhost:8080` reflexively.
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("--server must start with http:// or https://, got %q", globalFlags.Server)
	}
	url := server + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
}

func apiGet(path string) (map[string]interface{}, error) {
	return apiRequest("GET", path, "")
}

// apiGetRaw issues a GET and returns the raw response body bytes,
// for endpoints that don't return JSON (e.g. /zones/{name}/export
// emits BIND-format zone text with application/x-zone-file). Auth
// and base URL handling match apiRequest.
func apiGetRaw(path string) ([]byte, error) {
	server := strings.TrimRight(globalFlags.Server, "/")
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("--server must start with http:// or https://, got %q", globalFlags.Server)
	}
	url := server + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func apiPost(path, body string) (map[string]interface{}, error) {
	return apiRequest("POST", path, body)
}

func apiPut(path, body string) (map[string]interface{}, error) {
	return apiRequest("PUT", path, body)
}

func apiDelete(path, body string) (map[string]interface{}, error) {
	return apiRequest("DELETE", path, body)
}

func printJSON(key string, val interface{}, indent string) {
	switch v := val.(type) {
	case map[string]interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for k, vv := range v {
			printJSON(k, vv, indent+"  ")
		}
	case []interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for i, vv := range v {
			printJSON(fmt.Sprintf("[%d]", i), vv, indent+"  ")
		}
	default:
		fmt.Printf("%s%s: %v\n", indent, key, val)
	}
}
