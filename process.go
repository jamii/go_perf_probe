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
	TypePtr uint64
	NameOff uint64
	Name    string
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
		name := log.Name
		if log.Name == "" {
			name = readTypeName(firstmoduledata, noptrdata, rodata, log)
		}
		fmt.Printf("%#v %q\n", log, name)
	}

	return nil
}

func readTypeName(firstmoduledata elf.Symbol, noptrdata *elf.Section, rodata *elf.Section, log Log) string {
	if log.Name != "" {
		return log.Name
	}

	if log.TypePtr == 0 {
		return "<type not captured>"
	}

	modulePtr := firstmoduledata.Value
	for {
		// runtime.moduledata.types +296 uintptr
		typesPtr := readUint64(noptrdata, modulePtr-noptrdata.Addr+296)

		// runtime.moduledata.etypes +304 uintptr
		etypesPtr := readUint64(noptrdata, modulePtr-noptrdata.Addr+304)

		if log.TypePtr >= typesPtr && log.TypePtr < etypesPtr {
			len, bytesRead := readUvarint(rodata, typesPtr-rodata.Addr+log.NameOff+1) // varint?
			return readString(rodata, typesPtr-rodata.Addr+log.NameOff+1+uint64(bytesRead), int(len))
		} else {
			// runtime.moduledata.next +576 *moduledata
			modulePtr := readUint64(noptrdata, modulePtr-noptrdata.Addr+576)
			if modulePtr == 0 {
				return "<type not found>"
			}
		}
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
