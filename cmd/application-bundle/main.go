// application-bundle writes a clearly labeled interoperability fixture or verifies a bundle.
package main

import (
	"flag"
	"fmt"
	"os"
	"proxy-sentinel/internal/appdomain"
	"time"
)

func main() {
	output := flag.String("example-output", "", "write a synthetic interoperability fixture (not production rules)")
	communityOutput := flag.String("community-output", "", "write the reviewed NCU community starter bundle")
	verify := flag.String("verify", "", "verify an application-domain bundle")
	flag.Parse()
	var err error
	if *verify != "" {
		var raw []byte
		raw, err = os.ReadFile(*verify)
		if err == nil {
			var b *appdomain.Bundle
			b, err = appdomain.Verify(raw)
			if err == nil {
				fmt.Printf("schema=%s version=%s rules=%d\n", b.Manifest.SchemaVersion, b.Manifest.Version, len(b.Rules))
			}
		}
	} else if *communityOutput != "" {
		var raw []byte
		raw, err = appdomain.CommunityStarterBundle(time.Now())
		if err == nil {
			err = os.WriteFile(*communityOutput, raw, 0600)
		}
	} else if *output != "" {
		var raw []byte
		raw, err = appdomain.ExampleBundle(time.Now())
		if err == nil {
			err = os.WriteFile(*output, raw, 0600)
		}
	} else {
		err = fmt.Errorf("use --example-output, --community-output or --verify")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
