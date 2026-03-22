package utils

import (
	"bufio"
	"regexp"
	"strings"
)

// OutputParser provides utilities for parsing command outputs
type OutputParser struct{}

// NewOutputParser creates a new output parser
func NewOutputParser() *OutputParser {
	return &OutputParser{}
}

// ParseKeyValue parses output in "key value" format
func (p *OutputParser) ParseKeyValue(output []byte, separator string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, separator, 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			result[key] = value
		}
	}

	return result
}

// ParseRegex extracts values using regex patterns
func (p *OutputParser) ParseRegex(output []byte, pattern string) []map[string]string {
	var results []map[string]string
	regex := regexp.MustCompile(pattern)

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 1 {
			result := make(map[string]string)
			subexpNames := regex.SubexpNames()
			for i, match := range matches[1:] {
				if i+1 < len(subexpNames) && subexpNames[i+1] != "" {
					result[subexpNames[i+1]] = match
				}
			}
			if len(result) > 0 {
				results = append(results, result)
			}
		}
	}

	return results
}

// ParseTableFormat parses tabular output
func (p *OutputParser) ParseTableFormat(output []byte, headers []string) []map[string]string {
	var results []map[string]string
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= len(headers) {
			result := make(map[string]string)
			for i, header := range headers {
				if i < len(fields) {
					result[header] = fields[i]
				}
			}
			results = append(results, result)
		}
	}

	return results
}

// ProcessLinesWithFilter processes command output line by line with a filter function
func ProcessLinesWithFilter(output []byte, filter func(string) bool) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && filter(line) {
			result = append(result, line)
		}
	}

	return result
}

// ScanOutputLines scans output lines and returns those that pass the filter
func ScanOutputLines(output []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines
}

// FilterNonEmptyLines returns only non-empty lines from the input
func FilterNonEmptyLines(lines []string) []string {
	var result []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// SkipHeaderLine skips the first line (header) and returns the rest
func SkipHeaderLine(output []byte) []string {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var lines []string

	// Skip first line
	if scanner.Scan() {
		// Continue with remaining lines
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}
	}

	return lines
}
