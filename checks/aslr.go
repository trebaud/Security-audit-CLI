package checks

// aslr.go — Address Space Layout Randomization check
//
// WHY THIS MATTERS
// ASLR is a kernel mitigation that randomizes the memory addresses of key
// program segments (stack, heap, shared libraries, VDSO) each time a program
// runs. This makes it significantly harder for attackers to exploit memory
// corruption vulnerabilities such as buffer overflows or use-after-free bugs,
// because they cannot reliably predict where code or data will be in memory.
//
// Without ASLR, a known exploit that works on one machine will almost always
// work on another — addresses are static and predictable.
//
// HOW IT WORKS
// Reads the kernel sysctl value at /proc/sys/kernel/randomize_va_space.
// This file is exposed by the kernel on all modern Linux systems and requires
// no special privileges to read.
//
// VALUES
//   0 → disabled — no randomization at all (FAIL)
//   1 → partial  — stack, VDSO, mmap randomized but NOT heap (WARN)
//   2 → full     — stack, heap, mmap, VDSO all randomized (PASS, recommended)
//
// MAKING THE CHANGE PERSISTENT
//   echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf
//   sysctl -p

import (
	"os"
	"strings"
)

// ASLRCheck reads /proc/sys/kernel/randomize_va_space and checks its value.
type ASLRCheck struct{}

func (c *ASLRCheck) ID() string { return "aslr" }

func (c *ASLRCheck) Run() Task {
	const path = "/proc/sys/kernel/randomize_va_space"

	data, err := os.ReadFile(path)
	if err != nil {
		return Task{
			ID:          c.ID(),
			Name:        "ASLR",
			Description: "Address Space Layout Randomization",
			Status:      StatusSkipped,
			Message:     "Cannot read " + path,
			Details: []string{
				"  " + err.Error(),
				"  This path should always be readable on Linux. Check if /proc is mounted.",
			},
		}
	}

	value := strings.TrimSpace(string(data))
	switch value {
	case "2":
		return Task{
			ID:          c.ID(),
			Name:        "ASLR",
			Description: "Address Space Layout Randomization",
			Status:      StatusPass,
			Message:     "Full ASLR enabled (value=2)",
			Details: []string{
				"  WHY IT MATTERS",
				"  ASLR randomizes memory addresses, making memory corruption exploits",
				"  significantly harder. Without it, attackers can reliably jump to known",
				"  addresses (return-oriented programming, shellcode injection, etc.).",
				"",
				"  RESULT",
				"  " + path + " = 2",
				"  Full randomization is active: stack, heap, mmap, and VDSO",
				"  are all assigned random base addresses at each program load.",
			},
		}
	case "1":
		return Task{
			ID:          c.ID(),
			Name:        "ASLR",
			Description: "Address Space Layout Randomization",
			Status:      StatusWarn,
			Message:     "Partial ASLR only (value=1)",
			Details: []string{
				"  WHY IT MATTERS",
				"  Value 1 randomizes the stack, VDSO, and mmap, but the heap remains",
				"  at a static base address. Heap-spray and heap-overflow attacks can",
				"  still reliably target heap-allocated objects.",
				"",
				"  RESULT",
				"  " + path + " = 1  (partial — heap is NOT randomized)",
				"",
				"  REMEDIATION",
				"  Temporary:  echo 2 > " + path,
				"  Persistent: echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf",
				"              sysctl -p",
			},
			JSONDetails: path + " = 1 (heap not randomized)\nFix: echo 2 > " + path,
		}
	default:
		return Task{
			ID:          c.ID(),
			Name:        "ASLR",
			Description: "Address Space Layout Randomization",
			Status:      StatusFail,
			Message:     "ASLR disabled (value=" + value + ")",
			Details: []string{
				"  WHY IT MATTERS",
				"  With ASLR disabled (value=0), memory addresses are completely static.",
				"  Any memory corruption vulnerability becomes trivially exploitable",
				"  because attacker payloads can hardcode exact target addresses.",
				"",
				"  RESULT",
				"  " + path + " = " + value + "  (disabled — memory layout is fully predictable)",
				"",
				"  REMEDIATION",
				"  Temporary:  echo 2 > " + path,
				"  Persistent: echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf",
				"              sysctl -p",
			},
			JSONDetails: path + " = " + value + " (disabled)\nFix: echo 2 > " + path,
		}
	}
}
