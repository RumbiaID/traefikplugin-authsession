// Package plugindemo a demo plugin.
package plugindemo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Demo a Demo plugin.
type Auth struct {
	next http.Handler
	name string
}

// New created a new Auth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Auth{
		next: next,
		name: name,
	}, nil
}

func (a *Auth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// get request session
	sessionCookie, err := req.Cookie("session_id")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	if time.Now().After(sessionCookie.Expires) {
		forbidden(rw)
		return
	}
	sessionID := sessionCookie.Value

	// validate authorization token
	authorization := req.Header.Get("Authorization")
	if authorization == "" {
		forbidden(rw)
		return
	}
	bearerToken := strings.Split(authorization, " ")
	if len(bearerToken) < 2 {
		forbidden(rw)
		return
	}
	token := bearerToken[1]

	// get request IP
	ip := req.RemoteAddr

	// validate session
	isValid, err := validateSession(ctx, validateSessionReq{
		SessionID: sessionID,
		IPAddress: ip,
	}, token)
	if err != nil {
		internalServerError(rw, err)
		return
	}
	if !isValid {
		forbidden(rw)
		return
	}

	a.next.ServeHTTP(rw, req)
}

type validateSessionReq struct {
	SessionID string `json:"session_id"`
	IPAddress string `json:"ip_address"`
}

func validateSession(ctx context.Context, reqData validateSessionReq, token string) (bool, error) {
	client := http.Client{}

	payload, err := json.Marshal(reqData)
	if err != nil {
		return false, err
	}

	url := ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewBuffer(payload))
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusInternalServerError {
		return false, fmt.Errorf("failed to get session with status code: %d", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		return true, nil
	} else {
		return false, nil
	}
}

func forbidden(rw http.ResponseWriter) {
	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func internalServerError(rw http.ResponseWriter, err error) {
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}
