package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeployCommand_TLSPreflightValidation(t *testing.T) {
	t.Run("requires TLS to be enabled", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.DeploymentOptions.TLSPreflightEnabled = true
		cmd.args.ServiceOptions.TLSEnabled = false
		cmd.args.ServiceOptions.Hosts = []string{"example.com"}

		err := cmd.preRun(&cobra.Command{}, []string{"test-service"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tls-preflight requires TLS to be enabled")
	})

	t.Run("incompatible with custom TLS certificates", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.DeploymentOptions.TLSPreflightEnabled = true
		cmd.args.ServiceOptions.TLSEnabled = true
		cmd.args.ServiceOptions.Hosts = []string{"example.com"}
		cmd.args.ServiceOptions.TLSCertificatePath = "/path/to/cert.pem"

		err := cmd.preRun(&cobra.Command{}, []string{"test-service"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tls-preflight is not compatible with custom TLS certificates")
	})

	t.Run("valid with TLS enabled and no custom certs", func(t *testing.T) {
		cmd := newDeployCommand()
		cmd.args.DeploymentOptions.TLSPreflightEnabled = true
		cmd.args.ServiceOptions.TLSEnabled = true
		cmd.args.ServiceOptions.Hosts = []string{"example.com"}

		err := cmd.preRun(&cobra.Command{}, []string{"test-service"})
		require.NoError(t, err)
	})
}

func TestDeployCommand_CanonicalHostValidation(t *testing.T) {
	tests := []struct {
		name          string
		hosts         []string
		canonicalHost string
		expectError   bool
		expectedError string
	}{
		{
			name:          "valid canonical host in hosts list",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "example.com",
			expectError:   false,
		},
		{
			name:          "valid canonical host in hosts list with www",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "www.example.com",
			expectError:   false,
		},
		{
			name:          "canonical host not in hosts list",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "api.example.com",
			expectError:   true,
			expectedError: "canonical-host 'api.example.com' must be present in the hosts list: [example.com www.example.com]",
		},
		{
			name:          "canonical host empty with hosts",
			hosts:         []string{"example.com", "www.example.com"},
			canonicalHost: "",
			expectError:   false,
		},
		{
			name:          "canonical host with no hosts",
			hosts:         []string{},
			canonicalHost: "example.com",
			expectError:   false,
		},
		{
			name:          "both canonical host and hosts empty",
			hosts:         []string{},
			canonicalHost: "",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()

			cmd.args.ServiceOptions.Hosts = tt.hosts
			cmd.args.ServiceOptions.CanonicalHost = tt.canonicalHost
			cmd.args.ServiceOptions.TLSEnabled = false

			mockCmd := &cobra.Command{}

			err := cmd.preRun(mockCmd, []string{"test-service"})

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
