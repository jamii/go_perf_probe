package main

import (
	"debug/elf"
	"fmt"
)

func process() error {
	file, err := elf.Open("./main")
	if err != nil {
		return err
	}

	symbols, err := file.Symbols()
	if err != nil {
		return err
	}

	var firstmoduledata elf.Symbol
	for _, symbol := range symbols {
		if symbol.Name == "runtime.firstmoduledata" {
			firstmoduledata = symbol
			break
		}
	}

	//data := elf.Data()
	_ = firstmoduledata

	fmt.Println(firstmoduledata.Value)
	rodata := file.Section(".rodata")
	fmt.Println(rodata.Offset, rodata.Offset+rodata.Size)

	debug_ranges := file.Section(".debug_ranges")
	fmt.Println(debug_ranges.Offset, debug_ranges.Offset+debug_ranges.Size)

	return nil
}

func main() {
	err := process()
	if err != nil {
		panic(err)
	}
}
