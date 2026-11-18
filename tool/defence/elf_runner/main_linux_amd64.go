// Apply a selected seccomp policy before starting the adjacent program.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed profiles.json
var profilesData []byte

const (
	bpfLoadWord     = 0x20
	bpfEqual        = 0x15
	bpfAtLeast      = 0x35
	bpfReturn       = 0x06
	archAMD64       = 0xc000003e
	x32Bit          = 0x40000000
	killProcess     = 0x80000000
	deny            = 0x00050000 | uint32(syscall.EPERM)
	allow           = 0x7fff0000
	prSetSeccomp    = 22
	prSetNoNewPrivs = 38
	filterMode      = 2
	maxProgramSize  = 128 * 1024 * 1024
)

type policy struct {
	Version     int      `json:"version"`
	ProgramHash string   `json:"programSha256"`
	Groups      []string `json:"groups"`
}

func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && info.Mode().IsRegular() {
		return file, nil
	}
	file.Close()
	return nil, fmt.Errorf("expected a regular file: %s", path)
}

func readPolicy(path string) (policy, error) {
	var config policy
	file, err := openRegular(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return config, err
	}
	if len(raw) > 8192 {
		return config, fmt.Errorf("policy file is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return config, fmt.Errorf("unexpected data after policy")
	}
	if config.Version != 1 || len(config.ProgramHash) != sha256.Size*2 || len(config.Groups) == 0 {
		return config, fmt.Errorf("invalid policy")
	}
	return config, nil
}

func filterFor(ids []string) ([]syscall.SockFilter, error) {
	var profiles []struct {
		ID       string            `json:"id"`
		Syscalls map[string]uint32 `json:"syscalls"`
	}
	if err := json.Unmarshal(profilesData, &profiles); err != nil {
		return nil, err
	}
	known := make(map[string]map[string]uint32)
	for _, profile := range profiles {
		known[profile.ID] = profile.Syscalls
	}
	if len(ids) == 0 || len(ids) > len(known) {
		return nil, fmt.Errorf("invalid syscall group count")
	}
	seen := make(map[uint32]bool)
	var numbers []uint32
	for _, id := range ids {
		calls, ok := known[id]
		if !ok {
			return nil, fmt.Errorf("unknown syscall group: %s", id)
		}
		for _, number := range calls {
			if !seen[number] {
				seen[number] = true
				numbers = append(numbers, number)
			}
		}
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	filter := []syscall.SockFilter{
		{Code: bpfLoadWord, K: 4},
		{Code: bpfEqual, Jt: 1, K: archAMD64},
		{Code: bpfReturn, K: killProcess},
		{Code: bpfLoadWord},
		{Code: bpfAtLeast, Jf: 1, K: x32Bit},
		{Code: bpfReturn, K: killProcess},
	}
	for _, number := range numbers {
		filter = append(filter,
			syscall.SockFilter{Code: bpfEqual, Jf: 1, K: number},
			syscall.SockFilter{Code: bpfReturn, K: deny},
		)
	}
	return append(filter, syscall.SockFilter{Code: bpfReturn, K: allow}), nil
}

func run() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	directory := filepath.Dir(self)
	config, err := readPolicy(filepath.Join(directory, "policy.json"))
	if err != nil {
		return err
	}
	filter, err := filterFor(config.Groups)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "program.elf")
	program, err := openRegular(path)
	if err != nil {
		return err
	}
	defer program.Close()
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(program, maxProgramSize+1))
	if err != nil {
		return err
	}
	if n > maxProgramSize || hex.EncodeToString(digest.Sum(nil)) != config.ProgramHash {
		return fmt.Errorf("program.elf checksum mismatch")
	}

	// The thread that installs seccomp is the thread that calls exec.
	runtime.LockOSThread()
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("setting no_new_privs: %w", errno)
	}
	programFilter := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetSeccomp, filterMode, uintptr(unsafe.Pointer(&programFilter)), 0, 0, 0)
	runtime.KeepAlive(filter)
	if errno != 0 {
		return fmt.Errorf("installing seccomp filter: %w", errno)
	}
	// Use the ordinary on-disk file already opened and checked above.
	fdPath := "/proc/self/fd/" + strconv.FormatUint(uint64(program.Fd()), 10)
	return syscall.Exec(fdPath, append([]string{path}, os.Args[1:]...), os.Environ())
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "MetaAWD ELF protection: %v\n", err)
		os.Exit(126)
	}
}
