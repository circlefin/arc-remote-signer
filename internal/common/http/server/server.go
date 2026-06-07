// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server provides a default server for http services.
package server

import (
	"crypto/tls"
	"net/http"
	"time"
)

const (
	readTimeout  = 30 * time.Second
	writeTimeout = 30 * time.Second
	idleTimeout  = 30 * time.Second
)

// RequiredEngineParams defines required params for shared http server creation.
type RequiredEngineParams struct {
	ServerName string
	TLS        *tls.Config
}

// NewServer creates a new http server with the given parameters and handlers.
func NewServer(params RequiredEngineParams, handlers ...http.Handler) *http.Server {
	return &http.Server{
		TLSConfig:    params.TLS,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, handler := range handlers {
				handler.ServeHTTP(w, r)
			}
		}),
	}
}
