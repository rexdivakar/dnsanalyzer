package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDNSAnalyzer(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		checks  []string // Strings that should be in the output
	}{
		{
			name:    "Basic DNS Query",
			args:    []string{"-domain", "example.com"},
			wantErr: false,
			checks:  []string{"DNS Records", "A Records:", "DNS Resolution:"},
		},
		{
			name:    "Full Scan",
			args:    []string{"-domain", "example.com", "-full"},
			wantErr: false,
			checks:  []string{"SSL/TLS Information", "HTTP Information", "Email Security", "Open Ports", "Security Score"},
		},
		{
			name:    "Technology Detection",
			args:    []string{"-domain", "example.com", "-tech", "-http"},
			wantErr: false,
			checks:  []string{"Detected Technologies", "HTTP Information"},
		},
		{
			name:    "JSON Output",
			args:    []string{"-domain", "example.com", "-json"},
			wantErr: false,
			checks:  []string{`"domain": "example.com"`, `"dns_records":`},
		},
	}

	// Check if the binary exists
	binPath := "./dnsanalyzer"
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		// Try to build it
		buildCmd := exec.Command("go", "build", "-o", binPath)
		if err := buildCmd.Run(); err != nil {
			t.Fatalf("Failed to build binary: %v", err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binPath, tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			
			err := cmd.Run()
			if (err != nil) != tt.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				t.Logf("Stderr: %v", stderr.String())
				return
			}
			
			output := stdout.String()
			t.Logf("Output length: %d bytes", len(output))
			
			// Check for expected strings in output
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("Output does not contain expected string: %s", check)
					// Print first 500 chars of output to help debug
					if len(output) > 500 {
						t.Logf("Output preview: %s...", output[:500])
					} else {
						t.Logf("Output: %s", output)
					}
				}
			}
			
			// Additional test-specific checks
			if strings.Contains(tt.name, "Technology") {
				if !strings.Contains(output, "Detected Technologies") {
					t.Errorf("Technology scan didn't show 'Detected Technologies' section")
				}
			}
		})
	}
}

func TestDNSAnalyzerWithTimeout(t *testing.T) {
	// This test ensures the analyzer doesn't hang
	cmd := exec.Command("./dnsanalyzer", "-domain", "example.com", "-full")
	
	// Set a timeout
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}
	
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	
	select {
	case <-time.After(30 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("Failed to kill process: %v", err)
		}
		t.Fatal("Process timed out")
	case err := <-done:
		if err != nil {
			t.Fatalf("Process finished with error: %v", err)
		}
	}
}

// TestMultipleDomains tests the analyzer with different domains
func TestMultipleDomains(t *testing.T) {
	domains := []string{
		"example.com",
		"google.com",
		"github.com",
	}
	
	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			cmd := exec.Command("./dnsanalyzer", "-domain", domain)
			err := cmd.Run()
			if err != nil {
				t.Errorf("Failed to analyze domain %s: %v", domain, err)
			}
		})
	}
}