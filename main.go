package main

import (
	"fmt"
)

type Foo struct {
	bar int64
}

func main() {
	fmt.Println(make([]string, 10))
	fmt.Println(new(Foo))
}
