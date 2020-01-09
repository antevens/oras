package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	auth "github.com/deislabs/oras/pkg/auth/docker"

	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
)

// Validate and return TLS renegotiation settings
func GetRenegotiation(option string) (strategy tls.RenegotiationSupport, err error) {
	switch option {
	// RenegotiateNever disables renegotiation.
	case "RenegotiateNever":
		return tls.RenegotiateNever, nil
	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	case "RenegotiateOnceAsClient":
		return tls.RenegotiateOnceAsClient, nil
	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	case "RenegotiateFreelyAsClient":
		return tls.RenegotiateFreelyAsClient, nil
	}
        return tls.RenegotiateNever, fmt.Errorf("WARNING: invalid TLS Renegotiation strategy selected %v", option)
}



func newResolver(username, password string, renegotiate string, insecure bool, plainHTTP bool, configs ...string) remotes.Resolver {

	opts := docker.ResolverOptions{
		PlainHTTP: plainHTTP,
	}

	renegotiation, err := GetRenegotiation(renegotiate)
	if renegotiate != "" && err != nil {
		fmt.Fprintf(os.Stderr, "valid options include RenegotiateNever (default), RenegotiateOnceAsClient or RenegotiateFreelyAsClient %v\n", err)
	}

	client := http.DefaultClient
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Renegotiation:      renegotiation,
				InsecureSkipVerify: true,
			},
		}
	}
	opts.Client = client


	if username != "" || password != "" {
		opts.Credentials = func(hostName string) (string, string, error) {
			return username, password, nil
		}
		return docker.NewResolver(opts)
	}
	cli, err := auth.NewClient(configs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error loading auth file: %v\n", err)
	}
	resolver, err := cli.Resolver(context.Background(), client, plainHTTP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Error loading resolver: %v\n", err)
		resolver = docker.NewResolver(opts)
	}
	return resolver
}
