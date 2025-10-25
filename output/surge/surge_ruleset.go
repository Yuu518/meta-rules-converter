package surge

import (
	"net"
	"os"
	"strings"
)

func SaveSurgeRuleSet(rules []string, outputPath string) error {
	output := strings.Join(rules, "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(outputPath, []byte(output), 0666)
}

func FormatDomainRules(domainFull []string, domainSuffix []string) []string {
	var rules []string

	for _, domain := range domainFull {
		rules = append(rules, "DOMAIN,"+domain)
	}

	for _, domain := range domainSuffix {
		rules = append(rules, "DOMAIN-SUFFIX,"+domain)
	}

	return rules
}

func FormatIPRules(cidrs []string) []string {
	var rules []string

	for _, cidr := range cidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			ip = net.ParseIP(cidr)
		}

		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			rules = append(rules, "IP-CIDR,"+cidr)
		} else {
			rules = append(rules, "IP-CIDR6,"+cidr)
		}
	}

	return rules
}
