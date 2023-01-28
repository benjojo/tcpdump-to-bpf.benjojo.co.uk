package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"

	"github.com/ghedo/go.pkt/packet"
)

//go:embed index.html
var IndexPage string

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(IndexPage))
	})

	http.HandleFunc("/compile", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		o := WebsiteResp{}
		d, err := compileBPF(r.Form.Get("target"), r.Form.Get("link"))
		if err == nil {
			o.Iptables = d.Iptables
		} else {
			o.Error = err.Error()
		}

		json.NewEncoder(w).Encode(o)
	})

	http.ListenAndServe(":80", nil)
}

func compileBPF(filterString string, linkType string) (o FullyCompiledFilter, err error) {
	var media packet.Type
	media = packet.IPv4
	switch linkType {
	case "ipv4":
		media = packet.IPv4
	case "ipv6":
		media = packet.IPv6
	case "eth":
		media = packet.Eth
	case "raw":
		media = packet.Raw
	}

	oo := FullyCompiledFilter{}
	out, err := Compile(filterString, media, true)
	if err != nil {
		return oo, err
	}
	output := out.Data.Export()
	log.Printf("a %v ~ %v", output, filterString)
	oo.Opcodes = output
	oo.Iptables = out.ToIptables()
	out.Data.Cleanup()

	return oo, nil
}

type FullyCompiledFilter struct {
	Opcodes  []BPFopcode
	Iptables string
}

type WebsiteResp struct {
	Iptables string
	Error    string
	Disasm   string
}
