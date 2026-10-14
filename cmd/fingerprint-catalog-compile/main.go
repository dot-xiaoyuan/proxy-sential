package main

import (
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/fingerprint"
)

func main() {
	var c fingerprint.Catalog
	if err := json.NewDecoder(os.Stdin).Decode(&c); err != nil {
		panic(err)
	}
	fingerprint.PrepareCatalog(&c)
	data, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	if _, err = fingerprint.LoadCatalog(data); err != nil {
		panic(err)
	}
	fmt.Println(string(data))
}
