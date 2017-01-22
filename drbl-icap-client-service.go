/*
An example of how to use drbl check icap service.

Run this program and Squid on the same machine.
Put the following lines in squid.conf:

icap_enable on
icap_service service_req reqmod_precache icap://127.0.0.1:1344/drbl
adaptation_access service_req allow all

(The ICAP server needs to be started before Squid.)

Set your browser to use the Squid proxy.
*/

package main

import (
	"flag"
	"fmt"
	"github.com/elico/drbl-peer"
	"github.com/elico/icap"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var ISTag = "\"DRBL\""
var debug bool
var address string
var block_page string
var defaultAction string
var dbBaseUrl string
var bypassConnect bool
var icap_maxconn string
var logblocks bool
var bypassblocks bool
var logblocksFile string

var blockWeight int
var timeout int
var peersFileName string

var err error

var drblPeers *drblpeer.DrblPeers

func ProcessRequest(host string) (string, int64) {
	answer := "ALLOW"

	if debug {
		fmt.Fprintln(os.Stderr, "ERRlog: Proccessing host => \""+host+"\"")
	}
	block, weight := drblPeers.Check(host)
	if block {
		if !bypassblocks {
			answer = "BLOCK"
		}
		if debug {
			fmt.Println(host, "Weight is:", weight)
		}
		if logblocks {
			log.Println(host, " Weight is: ", weight)
		}
	}
	return answer, weight
}

func DrblCheck(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "SquidBlocker filter ICAP service")

	if debug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
		fmt.Fprintln(os.Stderr, req.Response)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD, RESPMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", icap_maxconn)
		h.Set("X-Include", "X-Client-IP, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id")
		w.WriteHeader(200, nil, false)
	case "REQMOD":

		// Check if the method is either OPTIONS\GET\POST\PUT etc
		// Also to analyse the request stucutre to verify what is the current one used
		// based on the RFC section at: http://tools.ietf.org/html/rfc7230#section-5.3
		// Treat the CONNECT method in a special way due to the fact that it cannot actually be modified.
		checkhost := ""
		port := ""
		answer := defaultAction
		var err error
		if debug {
			fmt.Fprintln(os.Stderr, "Default CASE. Request to host: ", req.Request.URL.Host+", Request Method: ", req.Request.Method)
			fmt.Fprintln(os.Stderr, "The full url from the ICAP client request: ", req.Request.URL.String())
		}

		if req.Request.Method == "CONNECT" && bypassConnect {
			w.WriteHeader(204, nil, false)
			return
		}

		//Special case of non http request  GET cache_object://localhost/info HTTP/1.0
		// This case should never happen!!!
		if strings.HasPrefix(req.Request.URL.String(), "cache_object://") {
			if debug {
				fmt.Fprintln(os.Stderr, "cache_object:// request and sending 204 back")
			}
			w.WriteHeader(204, nil, false)
			return
		}

		checkhost, port, err = net.SplitHostPort(req.Request.URL.Host)
		if err != nil {
			_ = err
			checkhost = req.Request.URL.Host
		}

		if len(port) > 0 && port != "0" && debug {
			fmt.Fprintln(os.Stderr, "Request with port: "+port)
		}
		answer, weigth := ProcessRequest(checkhost)

		if debug {
			fmt.Fprintln(os.Stderr, "reporting answer size => ", len(answer))
			fmt.Fprintln(os.Stderr, "reporitng answer =>", answer, ", for =>", req.Request.URL.String(), "with weight =>", weigth)
		}

		switch {
		case answer == "ALLOW":
			if debug {
				fmt.Fprintln(os.Stderr, "OK response and sending 204 back")
			}
			w.WriteHeader(204, nil, false)
			return

		case answer == "BLOCK":
			if debug {
				fmt.Fprintln(os.Stderr, "ERR response from DB. Sending 307 redirection back")
			}
			resp := new(http.Response)
			resp.Status = "SquidBlocker this url has been filtered!"
			resp.StatusCode = 307
			resp.Proto = req.Request.Proto
			resp.ProtoMajor = req.Request.ProtoMajor
			resp.ProtoMinor = req.Request.ProtoMinor
			redirectLocation, _ := url.Parse(block_page)
			redirectVars := url.Values{}
			redirectVars.Set("url", req.Request.URL.String())
			redirectVars.Set("domain", req.Request.URL.Host)
			redirectLocation.RawQuery = redirectVars.Encode()
			myMap := make(map[string][]string)
			//What if it is a connect request??
			myMap["Location"] = append(myMap["Location"], redirectLocation.String())
			resp.Header = myMap
			//resp.Body = ioutil.NopCloser(bytes.NewBufferString(body))
			//resp.ContentLength = int64(len(body))
			resp.Request = req.Request
			w.WriteHeader(200, resp, false)
			return
		default:
			if debug {
				fmt.Fprintln(os.Stderr, "Unknown asnwer and scenario, not adapting the request")
			}
			w.WriteHeader(204, nil, false)
			return
		}

	case "RESPMOD":
		w.WriteHeader(204, nil, false)
	case "ERRDUMMY":
		// Add a counter here
		if debug {
			fmt.Fprintln(os.Stderr, "ERRDUMMY Malformed request")
		}
		resp := new(http.Response)
		resp.Status = "SquidBlocker this url has been filtered!"
		resp.StatusCode = 307
		resp.Proto = "HTTP/1.0"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 0
		redirectLocation, _ := url.Parse(block_page)
		redirectVars := url.Values{}
		redirectVars.Set("url", "http://malformed-request/")
		redirectVars.Set("domain", "malformed-request")
		redirectVars.Set("error", "400")
		redirectLocation.RawQuery = redirectVars.Encode()
		myMap := make(map[string][]string)
		//What if it is a connect request??
		myMap["Location"] = append(myMap["Location"], redirectLocation.String())
		resp.Header = myMap
		resp.Request = req.Request
		w.WriteHeader(200, resp, false)
		if debug {
			fmt.Fprintln(os.Stderr, ": REQMOD: sent 200 (307 redirect -malformed) response to client")
		}
	default:
		w.WriteHeader(405, nil, false)
		if debug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func defaultIcap(w icap.ResponseWriter, req *icap.Request) {
	h := w.Header()
	h.Set("ISTag", ISTag)
	h.Set("Service", "DRBL default ICAP service")

	if debug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD, RESPMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", icap_maxconn)
		h.Set("This-Server", "Default ICAP url which bypass all requests adaptation")
		h.Set("X-Include", "X-Client-IP, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id, X-Server-IP")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		if debug {
			fmt.Fprintln(os.Stderr, "Default REQMOD, you should use the apropriate ICAP URL")
		}
		w.WriteHeader(204, nil, false)
	case "RESPMOD":
		if debug {
			fmt.Fprintln(os.Stderr, "Default RESPMOD, you should use the apropriate ICAP URL")
		}
		w.WriteHeader(204, nil, false)
	case "ERRDUMMY":
		// Add a counter here
		if debug {
			fmt.Fprintln(os.Stderr, "Default ERRDUMMY Malformed request, you should use the apropriate ICAP URL")
		}
		w.WriteHeader(204, nil, false)
	default:
		w.WriteHeader(405, nil, false)
		if debug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func init() {
	fmt.Fprintln(os.Stderr, "Starting DRBL ICAP service")

	flag.BoolVar(&debug, "debug", false, "Run in debug mode")
	flag.StringVar(&address, "icap-port", "127.0.0.1:1344", "Listening address for the ICAP service")
	flag.StringVar(&block_page, "blockpage", "http://ngtech.co.il/block_page/", "A url which will be used as a block page with the domains/host appended")
	flag.StringVar(&defaultAction, "default-action", "ALLOW", "Answer can be either \"ALLOW\" or \"BLOCK\"")
	flag.StringVar(&icap_maxconn, "icap-maxconn", "4000", "Maximum number of connections that the icap should handle")
	flag.BoolVar(&bypassConnect, "bypassconnect", false, "Bypass CONNECT requests modification. set \"1\" to enable")
	flag.BoolVar(&logblocks, "logblocks", false, "Log blacklisted domains into a log file. set \"1\" to enable")
	flag.StringVar(&logblocksFile, "logblocks-filename", "block-log.txt", "Blacklisted hosts log filename")

	flag.BoolVar(&bypassblocks, "bypassblocks", false, "Bypass actual blcoking to gather hosts for blacklist population using the log files. set \"1\" to enable")
	flag.IntVar(&blockWeight, "block-weight", 128, "Peers blacklist weight")
	flag.IntVar(&timeout, "query-timeout", 30, "Timeout for all peers response")
	flag.StringVar(&peersFileName, "peers-filename", "peersfile.txt", "Blacklists peers filename")

	flag.Parse()

	flagsMap := make(map[string]interface{})
	flagsMap["debug"] = debug
	flagsMap["icap-port"] = address
	flagsMap["blockpage"] = block_page
	flagsMap["default-action"] = defaultAction
	flagsMap["bypassconnect"] = bypassConnect
	flagsMap["icap-maxconn"] = icap_maxconn

	flagsMap["block-weight"] = blockWeight
	flagsMap["icap-port"] = address
	flagsMap["query-timeout"] = timeout
	flagsMap["peers-filename"] = peersFileName

	fmt.Fprintln(os.Stderr, "ERRlog: Config Variables:")

	for k, v := range flagsMap {
		fmt.Fprintf(os.Stderr, "ERRlog:\t%v =>  %v\n", k, v)
	}

}

func main() {
	f, err := os.OpenFile(logblocksFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
	fmt.Printf("error opening file: %v\n", err)
	}
	defer f.Close()
	log.SetOutput(f)
	log.Println("##This is a test log entry")

	fmt.Fprintln(os.Stderr, "Starting DRBL ICAP serivce :D")

	// Verify flags input
	switch {
	case defaultAction == "BLOCK":

	case defaultAction == "ALLOW":

	default:
		panic("Invalid filtering default answer")
	}

	drblPeers, _ = drblpeer.NewPeerListFromFile(peersFileName, int64(blockWeight), timeout, debug)
	if debug {
		fmt.Println("Peers", drblPeers)
	}

	icap.HandleFunc("/drbl", DrblCheck)
	icap.HandleFunc("/", defaultIcap)
	res := icap.ListenAndServe(address, nil)
	fmt.Println(res)
}
