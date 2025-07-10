package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	indexURL = "https://chaos-data.projectdiscovery.io/index.json"
	version  = "1.1.0"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// Helper functions for colored output
func printInfo(format string, args ...interface{}) {
	fmt.Printf(colorCyan+format+colorReset+"\n", args...)
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf(colorGreen+format+colorReset+"\n", args...)
}

func printWarning(format string, args ...interface{}) {
	fmt.Printf(colorYellow+format+colorReset+"\n", args...)
}

func printError(format string, args ...interface{}) {
	fmt.Printf(colorRed+format+colorReset+"\n", args...)
}

func printHeader(format string, args ...interface{}) {
	fmt.Printf(colorBold+colorPurple+format+colorReset+"\n", args...)
}

func printStats(format string, args ...interface{}) {
	fmt.Printf(colorBlue+format+colorReset+"\n", args...)
}

type Entry struct {
	Name        string `json:"name"`
	ProgramURL  string `json:"program_url"`
	URL         string `json:"URL"`
	Count       int    `json:"count"`
	Change      int    `json:"change"`
	IsNew       bool   `json:"is_new"`
	Platform    string `json:"platform"`
	Bounty      bool   `json:"bounty"`
	LastUpdated string `json:"last_updated"`
}

func main() {
	printHeader("ChaosDomainDumper version %s", version)

	resp, err := http.Get(indexURL)
	if err != nil {
		printError("Error fetching indexURL: %v", err)
		panic(err)
	}
	defer resp.Body.Close()
	printSuccess("indexURL '%s' successfully fetched (Status: %d)", indexURL, resp.StatusCode)

	var entries []Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		printError("Error decoding indexURL response: %v", err)
		panic(err)
	}
	printInfo("index.json contains %d entries", len(entries))

	var (
		totalPrograms   int
		updatedPrograms int
		totalFiles      int
		totalFQDNs      int
		totalNewFiles   int
		totalNewFQDNs   int
	)

	for _, entry := range entries {
		platform := sanitizeName(entry.Platform)
		if platform == "" {
			platform = "selfhosted"
		}
		name := sanitizeName(entry.Name)

		domainDir := filepath.Join(platform, "Domains", name)
		tempDir := filepath.Join(os.TempDir(), "chaos_temp", platform, name)

		os.MkdirAll(filepath.Dir(domainDir), 0755)
		os.MkdirAll(tempDir, 0755)

		printInfo("Checking for update for '%s' [%s]", entry.Name, entry.Platform)

		zipData, err := downloadFile(entry.URL)
		if err != nil {
			printError("Download error: %v", err)
			continue
		}

		extractZip(zipData, tempDir)

		date := time.Now().Format("2006-01-02")
		updateDir := filepath.Join(platform, "Updates"+"_"+date, name)

		newFiles, newFQDNs := copyNewDomains(tempDir, domainDir, updateDir)
		if newFiles > 0 || newFQDNs > 0 {
			printSuccess("Found updates: %d new files, %d new FQDNs", newFiles, newFQDNs)

			totalNewFiles += newFiles
			totalNewFQDNs += newFQDNs
		} else {
			os.RemoveAll(updateDir)
		}

		fileCount, fqdnCount := countDomainsAndFQDNs(tempDir)
		totalFiles += fileCount
		totalFQDNs += fqdnCount

		updatedPrograms++
		totalPrograms++

		os.RemoveAll(domainDir)
		os.Rename(tempDir, domainDir)
	}

	// Statistics
	printHeader("──────────────────────────────")
	printHeader("FINAL STATISTICS")
	printHeader("──────────────────────────────")
	printStats("Processed programs:             %d", totalPrograms)
	printStats("Programs with updates:          %d", updatedPrograms)
	printStats("Second-level domains (files):   %d", totalFiles)
	printStats("Total FQDNs (lines):            %d", totalFQDNs)
	printStats("New files (updates):            %d", totalNewFiles)
	printStats("New FQDNs (updates):            %d", totalNewFQDNs)
}

func countDomainsAndFQDNs(root string) (int, int) {
	fileCount := 0
	fqdnCount := 0

	filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			fileCount++
			lines, err := countLines(path)
			if err == nil {
				fqdnCount += lines
			}
		}
		return nil
	})
	return fileCount, fqdnCount
}

func countLines(filePath string) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := f.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		if err != nil {
			if err == io.EOF {
				break
			}
			return count, err
		}
	}
	return count, nil
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}

func downloadFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func extractZip(zipData []byte, outDir string) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		printError("Error extracting zip: %v", err)
		return
	}

	os.MkdirAll(outDir, 0755)

	for _, f := range r.File {
		path := filepath.Join(outDir, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		os.MkdirAll(filepath.Dir(path), 0755)
		outFile, err := os.Create(path)
		if err != nil {
			rc.Close()
			continue
		}

		io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
	}
}

func copyNewDomains(newDir, oldDir, updateDir string) (int, int) {
	newFileCount := 0
	newFQDNCount := 0

	printInfo("Processing: %s -> %s -> %s", newDir, oldDir, updateDir)
	filepath.WalkDir(newDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			printWarning("Error processing path: %v", err)
			return nil
		} else if d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(newDir, path)
		oldPath := filepath.Join(oldDir, relPath)
		destPath := filepath.Join(updateDir, relPath)

		if _, err := os.Stat(oldPath); os.IsNotExist(err) {
			// Datei existiert nicht im oldDir, komplett kopieren
			os.MkdirAll(filepath.Dir(destPath), 0755)
			copyFile(path, destPath)
			newFileCount++
			fqdnLines, _ := countLines(path)
			newFQDNCount += fqdnLines
			printSuccess("New file: %s (%d FQDNs)", relPath, fqdnLines)
		} else {
			// Datei existiert in beiden Verzeichnissen, Zeilen vergleichen
			newLines, err := getNewLines(path, oldPath)
			if err == nil && len(newLines) > 0 {
				os.MkdirAll(filepath.Dir(destPath), 0755)
				f, err := os.Create(destPath)
				if err == nil {
					for _, line := range newLines {
						f.WriteString(line + "\n")
					}
					f.Close()
					newFileCount++
					newFQDNCount += len(newLines)
					printSuccess("Updated file: %s (%d new FQDNs)", relPath, len(newLines))
				}
			}
		}
		return nil
	})

	return newFileCount, newFQDNCount
}

// Hilfsfunktion: Gibt alle Zeilen zurück, die in fileA, aber nicht in fileB sind
func getNewLines(fileA, fileB string) ([]string, error) {
	aLines, err := readLines(fileA)
	if err != nil {
		return nil, err
	}
	bLines, err := readLines(fileB)
	if err != nil {
		return nil, err
	}
	bSet := make(map[string]struct{}, len(bLines))
	for _, line := range bLines {
		bSet[line] = struct{}{}
	}
	var diff []string
	for _, line := range aLines {
		if _, found := bSet[line]; !found {
			diff = append(diff, line)
		}
	}
	return diff, nil
}

// Hilfsfunktion: Liest alle Zeilen einer Datei als Slice
func readLines(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	buf := make([]byte, 4096)
	var partial string
	for {
		n, err := f.Read(buf)
		if n > 0 {
			chunk := partial + string(buf[:n])
			parts := strings.Split(chunk, "\n")
			partial = parts[len(parts)-1]
			lines = append(lines, parts[:len(parts)-1]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return lines, err
		}
	}
	if partial != "" {
		lines = append(lines, partial)
	}
	return lines, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func countFilesInDir(root string) int {
	count := 0
	filepath.WalkDir(root, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			count++
		}
		return nil
	})
	return count
}
