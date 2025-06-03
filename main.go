package main

import (
	"fmt"
)

type Foo struct {
	bar int64
}

func main() {
	strings := make([]string, 5)
	for i := 0; i < 10; i += 1 {
		strings = append(strings, "foo")
	}
	fmt.Println(strings)
	fmt.Println(new(Foo))
}
