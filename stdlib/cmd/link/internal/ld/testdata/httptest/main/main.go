// A small test program that uses the net/http package. There is
// nothing special about net/http here, this is just a convenient way
// to pull in a lot of code.

package main

import (
	"github.com/runZeroInc/excrypto/stdlib/net/http"
	"github.com/runZeroInc/excrypto/stdlib/net/http/httptest"
)

type statusHandler int

func (h *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(int(*h))
}

func main() {
	status := statusHandler(http.StatusNotFound)
	s := httptest.NewServer(&status)
	defer s.Close()
}
