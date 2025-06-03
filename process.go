package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

func main() {
	err := readTypeNames()
	if err != nil {
		panic(err)
	}
}

func readTypeNames() error {
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

	noptrdata := file.Section(".noptrdata")
	rodata := file.Section(".rodata")

	fmt.Println(readTypeName(firstmoduledata, noptrdata, rodata, uint64(4842496), uint64(14192)))

	return nil
}

func readTypeName(firstmoduledata elf.Symbol, noptrdata *elf.Section, rodata *elf.Section, typePtr uint64, nameOff uint64) string {
	modulePtr := firstmoduledata.Value

	// runtime.moduledata.types +296 uintptr
	typesPtr := readUint64(noptrdata, modulePtr-noptrdata.Addr+296)

	// runtime.moduledata.etypes +304 uintptr
	etypesPtr := readUint64(noptrdata, modulePtr-noptrdata.Addr+304)

	if typePtr >= typesPtr && typePtr < etypesPtr {
		len, bytesRead := readUvarint(rodata, typesPtr-rodata.Addr+nameOff+1) // varint?
		return readString(rodata, typesPtr-rodata.Addr+nameOff+1+uint64(bytesRead), int(len))
	} else {
		panic("TODO moduledata.next")
	}
}

func readUint64(section *elf.Section, offset uint64) uint64 {
	var bytes [8]byte
	section.ReadAt(bytes[:], int64(offset))
	return binary.LittleEndian.Uint64(bytes[:])
}

func readUvarint(section *elf.Section, offset uint64) (uint64, int) {
	var bytes [binary.MaxVarintLen64]byte
	section.ReadAt(bytes[:], int64(offset))
	return binary.Uvarint(bytes[:])
}

func readString(section *elf.Section, offset uint64, len int) string {
	bytes := make([]byte, len)
	section.ReadAt(bytes, int64(offset))
	return string(bytes)
}
