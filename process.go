package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func main() {
	logs, err := trace()
	if err != nil {
		panic(err)
	}

	err = printTypeNames(logs)
	if err != nil {
		panic(err)
	}
}

type Log struct {
	Typ     uint64
	NameOff uint64
}

func trace() ([]Log, error) {
	cmd := exec.Command("sudo", "bpftrace", "-q", "./probe.bt")
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	logsJson := out.String()
	logs := make([]Log, 0, len(logsJson))
	for _, logJson := range strings.Split(logsJson, "\n") {
		if logJson == "" {
			continue
		}
		var log Log
		err := json.Unmarshal([]byte(logJson), &log)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

func printTypeNames(logs []Log) error {
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

	for _, log := range logs {
		fmt.Printf("%#v %q\n", log, readTypeName(firstmoduledata, noptrdata, rodata, log.Typ, log.NameOff))
	}

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
