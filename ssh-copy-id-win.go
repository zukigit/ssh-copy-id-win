package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	port := flag.Int("p", 22, "port")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s: [user@]hostname\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("flag.NArg()", flag.NArg())
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("os.flag.Arg(1)", flag.Arg(0))
	fmt.Println("port", *port)
}
