// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcache

import (
	"fmt"
	"sync/atomic"
)

var registeredCache Cache[int, int32]

func init() {
	registeredCache.Register()
}

var seq atomic.Uint32

func next[T int | int32]() *T {
	x := new(T)
	*x = T(seq.Add(1))
	return x
}

func str[T int | int32](x *T) string {
	if x == nil {
		return "nil"
	}
	return fmt.Sprint(*x)
}
