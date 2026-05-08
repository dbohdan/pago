// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dbohdan.com/pago"
	"dbohdan.com/pago/input"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

// ParseRecipients parses the entire text of an recipients file,
// supporting both X25519 and SSH public key formats.
func ParseRecipients(contents string) ([]age.Recipient, error) {
	lines := strings.Split(contents, "\n")
	recips := make([]age.Recipient, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var recipient age.Recipient
		var err error

		// First, try to parse as an X25519 recipient.
		recipient, err = age.ParseX25519Recipient(line)
		if err != nil {
			// If that fails, try parsing as an SSH public key.
			recipient, err = agessh.ParseRecipient(line)
			if err != nil {
				return nil, fmt.Errorf("invalid recipient: %w", err)
			}
		}

		recips = append(recips, recipient)
	}

	return recips, nil
}

// SaveEntry encrypts the provided password and saves it to a file in the password store.
func SaveEntry(recipientsPath, passwordStore, name, password string) error {
	recipientsData, err := os.ReadFile(recipientsPath)
	if err != nil {
		return fmt.Errorf("failed to read recipients file: %w", err)
	}

	recips, err := ParseRecipients(string(recipientsData))
	if err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	dest, err := pago.EntryFile(passwordStore, name)
	if err != nil {
		return fmt.Errorf("failed to get entry file path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dest), pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create output path: %w", err)
	}

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	w, err := age.Encrypt(armorWriter, recips...)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %w", err)
	}

	if _, err := io.WriteString(w, password); err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish encryption: %w", err)
	}

	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	if err := pago.WriteFileAtomic(dest, buf.Bytes(), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write entry file: %w", err)
	}

	return nil
}

// WrapDecrypt returns a reader that can decrypt data from the input reader.
// It automatically detects whether the input is in the armored or binary age format.
func WrapDecrypt(r io.Reader, identities ...age.Identity) (io.Reader, error) {
	buffer := make([]byte, len(armor.Header))

	// Check if the input starts with an armor header.
	n, err := io.ReadFull(r, buffer)
	if err != nil && !errors.Is(err, io.EOF) && n < len(armor.Header) {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	armored := string(buffer[:n]) == armor.Header
	r = io.MultiReader(bytes.NewReader(buffer[:n]), r)

	var reader io.Reader

	if armored {
		reader, err = age.Decrypt(armor.NewReader(r), identities...)
	} else {
		reader, err = age.Decrypt(r, identities...)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", pago.ErrDecryption, err)
	}

	return reader, nil
}

// ParseIdentities parses a string containing age identities and/or SSH private keys.
// It supports both native age X25519 identities and PEM-encoded SSH private keys.
func ParseIdentities(identityData string) ([]age.Identity, error) {
	lines := strings.Split(identityData, "\n")
	allIdentities := make([]age.Identity, 0, len(lines))
	var pemBlock []string
	inPEMBlock := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "-----BEGIN") {
			if inPEMBlock {
				return nil, errors.New("invalid PEM block: nested BEGIN")
			}

			inPEMBlock = true
			pemBlock = []string{line}

			continue
		}

		if inPEMBlock {
			pemBlock = append(pemBlock, line)

			if strings.HasPrefix(trimmedLine, "-----END") {
				inPEMBlock = false
				pemBytes := []byte(strings.Join(pemBlock, "\n"))

				id, err := agessh.ParseIdentity(pemBytes)
				if err != nil {
					return nil, fmt.Errorf("invalid SSH identity in PEM block: %w", err)
				}

				allIdentities = append(allIdentities, id)
				pemBlock = nil
			}

			continue
		}

		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// If it's not a PEM block, it must be a native age identity.
		id, err := age.ParseX25519Identity(trimmedLine)
		if err != nil {
			return nil, fmt.Errorf("invalid identity: %w", err)
		}

		allIdentities = append(allIdentities, id)
	}

	if inPEMBlock {
		return nil, errors.New("invalid PEM block: missing END")
	}

	return allIdentities, nil
}

// DecryptIdentities decrypts the identities file using a password provided by the user.
func DecryptIdentities(identitiesPath string) (string, error) {
	encryptedData, err := os.ReadFile(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to read identities file: %w", err)
	}

	password, err := input.SecureRead("Enter password to unlock identities: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	// Create a passphrase-based identity and decrypt the private keys with it.
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return "", fmt.Errorf("failed to create password-based identity: %w", err)
	}

	r, err := WrapDecrypt(bytes.NewReader(encryptedData), identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt identities: %w", err)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %w", err)
	}

	return string(decrypted), nil
}

// DecryptEntry decrypts a password entry from the store using identities from the identities file.
func DecryptEntry(identitiesPath, passwordStore, name string) (string, error) {
	file, err := pago.EntryFile(passwordStore, name)
	if err != nil {
		return "", fmt.Errorf("failed to get entry file path: %w", err)
	}

	encryptedData, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}

	identitiesText, err := DecryptIdentities(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt identities: %w", err)
	}

	ids, err := ParseIdentities(identitiesText)
	if err != nil {
		return "", fmt.Errorf("failed to parse identities: %w", err)
	}

	r, err := WrapDecrypt(bytes.NewReader(encryptedData), ids...)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	content, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %w", err)
	}

	return string(content), nil
}
