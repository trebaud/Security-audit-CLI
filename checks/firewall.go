package checks

// firewall.go — Firewall Status check
//
// WHY THIS MATTERS
// A firewall is the first line of defense against network-based attacks. It
// controls which network connections are allowed to reach the system, limiting
// the exposure of listening services to only the intended audiences.
//
// Without a firewall:
//   - All listening ports (including those bound to 0.0.0.0) are reachable by
//     anyone who can route to the machine.
//   - A misconfigured or vulnerable service is immediately exploitable without
//     any network-level barrier.
//   - Lateral movement between compromised hosts in the same network is trivial.
//
// HOW IT WORKS
// Probes the three most common Linux firewall tools in priority order:
//  1. ufw   — Debian/Ubuntu friendly frontend to iptables/nftables
//  2. nft   — nftables, the modern replacement for iptables (RHEL 8+, etc.)
//  3. iptables — traditional packet-filtering framework
//
// Each is called with a read-only status/list command. The first one found
// and active determines the result. If none are active, the check FAILs.

import (
	"os/exec"
	"strings"
)

// FirewallCheck probes ufw, nftables, and iptables in order to determine
// whether any packet-filtering rules are currently active.
type FirewallCheck struct{}

func (c *FirewallCheck) ID() string { return "firewall" }

func (c *FirewallCheck) Run() Task {
	// --- 1. Try ufw ---
	// ufw is available on Debian/Ubuntu. Its status output always begins with
	// "Status: active" or "Status: inactive".
	if out, err := exec.Command("ufw", "status").Output(); err == nil {
		text := string(out)
		if strings.Contains(strings.ToLower(text), "status: active") {
			return Task{
				ID:          c.ID(),
				Name:        "Firewall",
				Description: "Verify a firewall is active",
				Status:      StatusPass,
				Message:     "ufw is active",
				Details: append([]string{
					"  WHY IT MATTERS",
					"  A firewall restricts which network connections reach this host,",
					"  reducing the attack surface of all listening services.",
					"",
					"  RESULT — ufw is active. Current ruleset:",
					"",
				}, prefixLines(strings.TrimSpace(text), "  ")...),
			}
		}
		// ufw is installed but not enabled — explicit FAIL because the tool
		// is present but provides zero protection.
		return Task{
			ID:          c.ID(),
			Name:        "Firewall",
			Description: "Verify a firewall is active",
			Status:      StatusFail,
			Message:     "ufw is installed but INACTIVE",
			Details: []string{
				"  WHY IT MATTERS",
				"  ufw is installed but not running — no packet filtering is in effect.",
				"  All listening ports are fully exposed to the network.",
				"",
				"  ufw reported: " + strings.TrimSpace(text),
				"",
				"  REMEDIATION",
				"  Enable ufw:     ufw enable",
				"  Allow SSH first: ufw allow ssh  (to avoid locking yourself out)",
			},
			JSONDetails: "ufw installed but inactive\nFix: ufw allow ssh && ufw enable",
		}
	}

	// --- 2. Try nftables ---
	// nft list ruleset prints the full ruleset. An empty output means nft is
	// present but has no rules loaded.
	if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		text := strings.TrimSpace(string(out))
		if text != "" {
			return Task{
				ID:          c.ID(),
				Name:        "Firewall",
				Description: "Verify a firewall is active",
				Status:      StatusPass,
				Message:     "nftables ruleset is loaded",
				Details: append([]string{
					"  WHY IT MATTERS",
					"  A firewall restricts which network connections reach this host.",
					"",
					"  RESULT — nftables ruleset is active:",
					"",
				}, prefixLines(text, "  ")...),
			}
		}
		return Task{
			ID:          c.ID(),
			Name:        "Firewall",
			Description: "Verify a firewall is active",
			Status:      StatusWarn,
			Message:     "nftables present but ruleset is empty",
			Details:     []string{"  Fix: define rules in /etc/nftables.conf"},
			JSONDetails: "nftables installed but ruleset is empty\nFix: define rules in /etc/nftables.conf && systemctl enable --now nftables",
		}
	}

	// --- 3. Try iptables ---
	// iptables -L shows the current rule chains. A default install with only
	// the three built-in chains (INPUT, FORWARD, OUTPUT) and no actual rules
	// means there is no effective filtering.
	if out, err := exec.Command("iptables", "-L", "-n", "--line-numbers").Output(); err == nil {
		text := string(out)
		// Determine if any real rules exist beyond the default chain headers.
		hasRules := false
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Chain") ||
				strings.HasPrefix(line, "target") ||
				strings.TrimSpace(line) == "" {
				continue
			}
			hasRules = true
			break
		}
		if hasRules {
			return Task{
				ID:          c.ID(),
				Name:        "Firewall",
				Description: "Verify a firewall is active",
				Status:      StatusPass,
				Message:     "iptables rules are loaded",
				Details: append([]string{
					"  WHY IT MATTERS",
					"  A firewall restricts which network connections reach this host.",
					"",
					"  RESULT — iptables rules are active:",
					"",
				}, prefixLines(strings.TrimSpace(text), "  ")...),
			}
		}
		return Task{
			ID:          c.ID(),
			Name:        "Firewall",
			Description: "Verify a firewall is active",
			Status:      StatusWarn,
			Message:     "iptables present but no rules defined",
			Details:     []string{"  All chains use default ACCEPT policy with no rules", "  Fix: add iptables rules or install ufw/nftables"},
			JSONDetails: "iptables installed but all chains use default ACCEPT — no rules active\nFix: add iptables rules or install ufw/nftables",
		}
	}

	// None of the three tools responded — no firewall at all.
	return Task{
		ID:          c.ID(),
		Name:        "Firewall",
		Description: "Verify a firewall is active",
		Status:      StatusFail,
		Message:     "No firewall detected (ufw/nft/iptables)",
		Details: []string{
			"  WHY IT MATTERS",
			"  No firewall was detected. All listening ports are directly reachable",
			"  by any host that can route to this machine.",
			"  This is a significant risk, especially on internet-facing systems.",
			"",
			"  Probed (in order): ufw, nftables, iptables — none found or active.",
			"",
			"  REMEDIATION",
			"  Debian/Ubuntu:  apt install ufw && ufw allow ssh && ufw enable",
			"  RHEL/Fedora:    dnf install firewalld && systemctl enable --now firewalld",
		},
		JSONDetails: "No firewall active (probed: ufw, nftables, iptables)\nFix (Debian/Ubuntu): apt install ufw && ufw allow ssh && ufw enable\nFix (RHEL/Fedora): dnf install firewalld && systemctl enable --now firewalld",
	}
}

// prefixLines prepends prefix to every line in s (split on newlines).
// Used to indent multi-line tool output inside the Details field.
func prefixLines(s, prefix string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = prefix + l
	}
	return out
}
