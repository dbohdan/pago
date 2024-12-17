// pago - a command-line password manager.
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Parse the entire text of an age recipients file.
func parseRecipients(contents string) ([]age.Recipient, error) {
	var recips []age.Recipient

	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		recipient, err := age.ParseX25519Recipient(line)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient: %v", err)
		}

		recips = append(recips, recipient)
	}

	return recips, nil
}

// Encrypt the password and save it to a file.
func savePassword(recipients, passwordStore, name, password string) error {
	recipientsData, err := os.ReadFile(recipients)
	if err != nil {
		return fmt.Errorf("failed to read recipients file: %v", err)
	}

	recips, err := parseRecipients(string(recipientsData))
	if err != nil {
		return err
	}

	dest := passwordFile(passwordStore, name)
	err = os.MkdirAll(filepath.Dir(dest), dirPerms)

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()
	armorWriter := armor.NewWriter(f)

	w, err := age.Encrypt(armorWriter, recips...)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %v", err)
	}

	if _, err := io.WriteString(w, password); err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish encryption: %v", err)
	}

	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	return nil
}

// Returns a reader that can handle both armored and binary age files.
func wrapDecrypt(r io.Reader, identities ...age.Identity) (io.Reader, error) {
	buffer := make([]byte, len(armor.Header))

	// Check if the input starts with an armor header.
	n, err := io.ReadFull(r, buffer)
	if err != nil && !errors.Is(err, io.EOF) && n < len(armor.Header) {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	armored := string(buffer[:n]) == armor.Header
	r = io.MultiReader(bytes.NewReader(buffer[:n]), r)

	if armored {
		return age.Decrypt(armor.NewReader(r), identities...)
	}

	return age.Decrypt(r, identities...)
}

func decryptIdentities(identitiesPath string) (string, error) {
	encryptedData, err := os.ReadFile(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to read identities file: %v", err)
	}

	password, err := secureRead("Enter password to unlock identities: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	// Create a passphrase-based identity and decrypt the private keys with it.
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return "", fmt.Errorf("failed to create password-based identity: %v", err)
	}

	r, err := wrapDecrypt(bytes.NewReader(encryptedData), identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt identities: %v", err)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %v", err)
	}

	return string(decrypted), nil
}

func decryptPassword(agentSocket, identities, passwordStore, name string) (string, error) {
	encryptedData, err := os.ReadFile(passwordFile(passwordStore, name))
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %v", err)
	}

	// If an agent socket is configured, try to use the agent.
	if agentSocket != "" {
		if err := pingAgent(agentSocket); err != nil {
			// Ping failed.
			// Attempt to start the agent.
			identitiesText, err := decryptIdentities(identities)
			if err != nil {
				return "", err
			}

			if err := startAgentProcess(agentSocket, identitiesText); err != nil {
				return "", fmt.Errorf("failed to start agent: %v", err)
			}
		}

		password, err := decryptWithAgent(agentSocket, encryptedData)
		if err != nil {
			return "", err
		}

		return password, nil
	}

	// When no agent socket is configured, decrypt directly.
	// Decrypt the password-protected identities file first.
	identitiesText, err := decryptIdentities(identities)
	if err != nil {
		return "", err
	}

	ids, err := age.ParseIdentities(strings.NewReader(identitiesText))
	if err != nil {
		return "", fmt.Errorf("failed to parse identities: %v", err)
	}

	r, err := wrapDecrypt(bytes.NewReader(encryptedData), ids...)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	password, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %v", err)
	}

	return string(password), nil
}
