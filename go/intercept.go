package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// listenAndOpen serves the callback and opens the browser at authURL.
// http://localhost redirects use the default browser; anything else is intercepted
// in a private Edge/Chrome instance that maps the redirect host to a local listener.
func listenAndOpen(server *http.Server, redirectURI string, listenPort int, authURL string) (func(), error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect uri: %w", err)
	}

	if u.Scheme != "http" || !isLoopback(u.Hostname()) {
		return intercept(server, u, listenPort, authURL)
	}

	ln, err := net.Listen("tcp", listenAddr(redirectURI, listenPort))
	if err != nil {
		return nil, err
	}
	go server.Serve(ln)

	fmt.Println("Opening browser...")
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Open manually: %s\n", authURL)
	}
	return func() { server.Shutdown(context.Background()) }, nil
}

func intercept(server *http.Server, u *url.URL, listenPort int, authURL string) (func(), error) {
	browser := findBrowser()
	if browser == "" {
		return nil, fmt.Errorf("intercepting %s requires Edge or Chrome, none found", u.Host)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		return nil, err
	}

	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}

	dir, err := os.MkdirTemp("", "oidc-tool-")
	if err != nil {
		ln.Close()
		return nil, err
	}

	// --user-data-dir also forces a separate browser instance, which the flags below need.
	args := []string{
		"--user-data-dir=" + dir,
		fmt.Sprintf("--host-resolver-rules=MAP %s:%s %s", u.Hostname(), port, ln.Addr()),
		"--no-proxy-server", // a proxy would resolve the host itself and bypass the MAP rule
		"--no-first-run",
		"--no-default-browser-check",
	}

	if u.Scheme == "https" {
		cert, spki, err := selfSignedCert(u.Hostname())
		if err != nil {
			ln.Close()
			os.RemoveAll(dir)
			return nil, err
		}
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		// Trusts only this throwaway key, only in this browser instance.
		args = append(args, "--ignore-certificate-errors-spki-list="+spki)
		go server.ServeTLS(ln, "", "")
	} else {
		go server.Serve(ln)
	}

	cmd := exec.Command(browser, append(args, authURL)...)
	fmt.Printf("Intercepting %s://%s:%s -> %s\n", u.Scheme, u.Hostname(), port, ln.Addr())
	fmt.Printf("Opening %s...\n", filepath.Base(browser))
	if err := cmd.Start(); err != nil {
		server.Close()
		os.RemoveAll(dir)
		return nil, err
	}

	return func() {
		server.Shutdown(context.Background())
		cmd.Process.Kill()
		cmd.Wait()
		// Browser child processes may hold profile files briefly after the main process exits.
		for i := 0; i < 20 && os.RemoveAll(dir) != nil; i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func findBrowser() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, rel := range []string{`Microsoft\Edge\Application\msedge.exe`, `Google\Chrome\Application\chrome.exe`} {
			for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LocalAppData"} {
				if base := os.Getenv(env); base != "" {
					candidates = append(candidates, filepath.Join(base, rel))
				}
			}
		}
	case "darwin":
		candidates = []string{
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		}
	default:
		for _, name := range []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser"} {
			if p, err := exec.LookPath(name); err == nil {
				return p
			}
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// selfSignedCert returns an in-memory certificate for host and its base64 SHA-256 SPKI hash.
func selfSignedCert(host string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, base64.StdEncoding.EncodeToString(sum[:]), nil
}
