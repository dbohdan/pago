package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	checksumFilename = "SHA256SUMS.txt"
	dirPerms         = 0o755
	distDir          = "dist"
	filePerms        = 0o644
	projectName      = "pago"
	sshKey           = ".ssh/git"
)

var (
	pkgs = []string{"./cmd/pago", "./cmd/pago-agent"}
)

type BuildTarget struct {
	os   string
	arch string
}

func main() {
	if err := buildAll(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func buildAll() error {
	version := os.Getenv("VERSION")
	if version == "" {
		return errors.New("'VERSION' environment variable must be set")
	}

	releaseDir := filepath.Join(distDir, version)
	checksumFilePath := filepath.Join(releaseDir, checksumFilename)

	if err := os.MkdirAll(releaseDir, dirPerms); err != nil {
		return fmt.Errorf("failed to create release directory: %w", err)
	}

	targets := []BuildTarget{
		{"android", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"freebsd", "amd64"},
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"linux", "riscv64"},
		{"netbsd", "amd64"},
		{"openbsd", "amd64"},
	}

	for i, target := range targets {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("Building for %s/%s:\n", target.os, target.arch)

		arch, system := userArchAndSystem(target)
		targetDir := filepath.Join(
			releaseDir,
			fmt.Sprintf("%s-v%s-%s-%s", projectName, version, system, arch),
		)

		if err := os.MkdirAll(targetDir, dirPerms); err != nil {
			return fmt.Errorf("failed to create target directory: %w", err)
		}

		var buildErrors []error
		for _, pkg := range pkgs {
			outputPath, err := build(target, targetDir, pkg)
			if err != nil {
				buildErrors = append(buildErrors, fmt.Errorf("build failed for %s on %s/%s: %w", pkg, target.os, target.arch, err))
			}

			if err := appendChecksum(checksumFilePath, outputPath); err != nil {
				return err
			}
		}

		if len(buildErrors) > 0 {
			return errors.Join(buildErrors...)
		}

		zipPath := targetDir + ".zip"
		if err := zipDirectory(zipPath, targetDir); err != nil {
			return fmt.Errorf("failed to create ZIP archive: %w", err)
		}

		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("failed to remove target directory after archive creation: %w", err)
		}
	}

	fmt.Println()
	if err := signFile(filepath.Join(releaseDir, checksumFilename)); err != nil {
		return fmt.Errorf("signing failed: %v\n", err)
	}

	return nil
}

// userArchAndSystem maps GOARCH and GOOS to user-facing names.
func userArchAndSystem(target BuildTarget) (string, string) {
	arch := target.arch
	system := target.os

	if arch == "386" {
		arch = "x86"
	}
	if system == "darwin" {
		system = "macos"
	}
	if (system == "linux" || system == "macos") && arch == "amd64" {
		arch = "x86_64"
	}
	if system == "linux" && arch == "arm64" {
		arch = "aarch64"
	}

	return arch, system
}

func build(target BuildTarget, dir, pkg string) (string, error) {
	fmt.Printf("    - %s\n", pkg)

	ext := ""
	if target.os == "windows" {
		ext = ".exe"
	}

	outputPath := filepath.Join(dir, filepath.Base(pkg)+ext)

	cmd := exec.Command("go", "build", "-trimpath", "-o", outputPath, pkg)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", target.os),
		fmt.Sprintf("GOARCH=%s", target.arch),
		"CGO_ENABLED=0",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build command failed: %w (output: %q)", err, output)
	}

	return outputPath, nil
}

func zipDirectory(zipPath, dirPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create ZIP file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Use a relative path in the ZIP archive.
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %v", err)
		}

		// Create an entry with the original modification time.
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("failed to create ZIP header: %v", err)
		}

		header.Method = zip.Deflate
		header.Name = filepath.Join(filepath.Base(dirPath), relPath)
		zipEntry, err := zipWriter.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create ZIP entry: %v", err)
		}

		// Write the file contents.
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file for zipping: %v", err)
		}
		defer file.Close()

		if _, err := io.Copy(zipEntry, file); err != nil {
			return fmt.Errorf("failed to write zip entry: %v", err)
		}

		return nil
	})

	return err
}

func appendChecksum(checksumFilePath, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for checksumming: %v", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to calculate hash: %v", err)
	}

	hash := hex.EncodeToString(h.Sum(nil))

	relPath, err := filepath.Rel(filepath.Dir(checksumFilePath), filePath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %v", err)
	}
	checksumLine := fmt.Sprintf("%s  %s\n", hash, relPath)

	f, err = os.OpenFile(checksumFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerms)
	if err != nil {
		return fmt.Errorf("failed to open checksum file: %w", err)
	}
	defer f.Close()

	if _, err := io.WriteString(f, checksumLine); err != nil {
		return fmt.Errorf("failed to write checksum: %w", err)
	}

	return nil
}

func signFile(filePath string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	fmt.Printf("Signing %s\n", filePath)

	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "file", "-f", filepath.Join(homeDir, sshKey), filePath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
