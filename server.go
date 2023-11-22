// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"os"
	"time"

	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/http2"

	lru "github.com/hashicorp/golang-lru"
)

const ()

var (
	httpPort    = flag.String("http_port", ":8080", "HTTP Server Port")
	issuer      = flag.String("issuer", "", "Certificate Issuer PEM file")
	ocsp_bucket = flag.String("ocsp_bucket", "", "GCS Bucket with OCSP Responses")
	cache_size  = flag.Int("cache_size", 2000, "LRU Cache Size")
	debug       = flag.Bool("debug", false, "Enable debug logging")

	storageClient *storage.Client
	bucketHandle  *storage.BucketHandle
	issuerCert    *x509.Certificate

	cache  *lru.Cache
	logger slog.Logger
)

func defaulthandler(w http.ResponseWriter, r *http.Request) {

	var body []byte
	var err error

	// https://tools.ietf.org/html/rfc2560#appendix-A.1.1
	if r.Method == http.MethodPost {
		// openssl sends the cert in POST
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Error("Error: Unable to read ocsp POST request", "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodGet {
		rawReq := strings.TrimPrefix(r.URL.Path, "/")
		rc, err := base64.StdEncoding.DecodeString(rawReq)
		if err != nil {
			logger.Error("Error: unable to read ocsp GET request", "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		body = rc
	} else {
		logger.Error("Error: OCSP request must be GET or POST", "error", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	logger.Debug("Incoming OCSP Request", "request", base64.StdEncoding.EncodeToString(body))
	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		logger.Error("Could not parse OCSP Request", "error", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	gcsFilename := generateCanonicalFilename(ocspReq)
	logger.Info("Handling OCSP Request", "key", gcsFilename)

	// TODO validate that this request is intended for a CA this  OCSP server is responsible for
	// eg comppare ocspReq.IssuerKeyHash hash of the *issuer argument

	if ae, ok := cache.Get(fmt.Sprintf("%x", gcsFilename)); ok {
		cachedResponse := ae.([]byte)
		logger.Debug("Found OCSP Response in cache", "key", gcsFilename)
		ocspResp, err := ocsp.ParseResponse(cachedResponse, issuerCert)
		if err != nil {
			logger.Error("Could not read GCS Response Object Body", "error", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ocspResp.NextUpdate.Before(time.Now()) {
			logger.Info("Certificate stale: Removing from Cache", "key", gcsFilename)
			cache.Remove(gcsFilename)
			// TODO: emit pubsub message where the subscriber can regenerate a new OCSP Response given the serial_number
			// doing so will create a more dynamic OCSP system which will update responses before the batch OCSP Generator runs.
		} else {
			if r.Method == http.MethodGet {
				expireAt := ocspResp.NextUpdate.Format(http.TimeFormat)
				w.Header().Set("Expires", expireAt)
				w.Header().Set("Cache-Control", "public")
			}
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.Write(cachedResponse)
			return
		}
	}

	logger.Debug("Looking up OCSP Response in GCS", "key", gcsFilename)
	start := time.Now()
	obj := bucketHandle.Object(gcsFilename)
	rr, err := obj.NewReader(r.Context())
	if err != nil {
		logger.Error("Could not find OCSP Response Object", "error", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else {
		logger.Debug("Found OCSP Response in GCS", "key", gcsFilename)
	}
	defer rr.Close()

	rawOCSP, err := ioutil.ReadAll(rr)
	if err != nil {
		logger.Error("Could not read GCS Response Object Body", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Only parsing the response back out again to get the time for the NextUpdate to set as Cache-Control header
	// if thats not needed, skip this step (infact, no need to specify issuerCert)
	// The other better way to do this is to set this as an  metadata filed on the GCS object itself during pregeneration
	// phase...this is a TODO for later...
	ocspResp, err := ocsp.ParseResponse(rawOCSP, issuerCert)
	if err != nil {
		logger.Error("Could not parse OCSP Response from GCS", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	elapsed := time.Since(start)
	logger.Debug("OCSP lookup finished", "elapsed", elapsed)

	logger.Debug("Returning OCSP Response", "response", base64.StdEncoding.EncodeToString(rawOCSP))

	cache.Add(fmt.Sprintf("%x", gcsFilename), rawOCSP)

	if r.Method == http.MethodGet {
		expireAt := ocspResp.NextUpdate.Format(http.TimeFormat)
		w.Header().Set("Expires", expireAt)
	}
	w.Header().Set("Cache-Control", "public")
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(rawOCSP)
}

func generateUrlFilename(req []byte) string {
	return base64.RawURLEncoding.EncodeToString(req)
}
func generateCanonicalFilename(ocspReq *ocsp.Request) string {
	nameHash := hex.EncodeToString(ocspReq.IssuerNameHash)
	keyHash := hex.EncodeToString(ocspReq.IssuerKeyHash)
	serialNumber := ocspReq.SerialNumber.Text(16)
	return nameHash + "." + keyHash + "/" + serialNumber
}

func main() {

	flag.Parse()
	var err error

	if *debug {
		logger = *slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = *slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	if os.Getenv("OCSP_BUCKET") != "" && *ocsp_bucket == "" {
		*ocsp_bucket = os.Getenv("OCSP_BUCKET")
	}

	if *ocsp_bucket == "" {
		logger.Error("Either --ocsp_bucket or OCSP_BUCKET environment variable must be set")
	}

	if *issuer != "" {
		certPEM, err := ioutil.ReadFile(*issuer)
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			logger.Error("failed to parse certificate PEM")
		}
		issuerCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("failed to parse certificate", "error", err)
		}
	} else {
		issuerCert = nil
	}
	cache, err = lru.New(*cache_size)
	if err != nil {
		logger.Error("Could not initialize Cache", "error", err)
	} else {
		logger.Info("Initialized LRU cache", "size", *cache_size)
	}
	r := mux.NewRouter()
	r.HandleFunc("/", defaulthandler)
	r.NotFoundHandler = http.HandlerFunc(defaulthandler)

	ctx := context.Background()

	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		logger.Error("Could not init gcs client", "error", err)
	} else {
		logger.Info("Initialized Google Cloud Storage", "bucket", *ocsp_bucket)
	}
	bucketHandle = storageClient.Bucket(*ocsp_bucket)

	logger.Info("Starting OCSP Server", "port", *httpPort)

	httpSrv := &http.Server{
		Addr:    *httpPort,
		Handler: r,
	}
	http2.ConfigureServer(httpSrv, &http2.Server{})

	err = httpSrv.ListenAndServe()
	if err != nil {
		logger.Error("Web server (HTTP): ", "error", err)
	}

}
