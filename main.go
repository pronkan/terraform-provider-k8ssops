package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/pronkan/terraform-provider-k8ssops/internal/provider"
)

// Run the docs generation tool, version 0.1.0:
// go generate ./...

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/pronkan/k8ssops",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New("unknown"), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
