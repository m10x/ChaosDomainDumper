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
	indexURL    = "https://chaos-data.projectdiscovery.io/index.json"
	dataDir     = "data"
	lastRunFile = "data/last_run.txt"
)

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
	os.MkdirAll(dataDir, 0755)

	var lastRun time.Time
	if b, err := os.ReadFile(lastRunFile); err == nil {
		lastRun, _ = time.Parse(time.RFC3339, string(b))
	}

	resp, err := http.Get(indexURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var entries []Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		panic(err)
	}

	var (
		totalPrograms   int
		updatedPrograms int
		totalFiles      int
		totalFQDNs      int
		totalNewFiles   int
		totalNewFQDNs   int
	)

	for _, entry := range entries {
		entryUpdated, err := time.Parse(time.RFC3339, entry.LastUpdated)
		if err != nil {
			fmt.Println("Ungültiges Datum für:", entry.Name)
			continue
		}

		if !lastRun.IsZero() && !entryUpdated.After(lastRun) {
			continue
		}

		platform := sanitizeName(entry.Platform)
		if platform == "" {
			platform = "selfhosted"
		}
		name := sanitizeName(entry.Name)

		domainDir := filepath.Join(platform, "Domains", name)
		tempDir := filepath.Join(os.TempDir(), "chaos_temp", platform, name)

		os.MkdirAll(filepath.Dir(domainDir), 0755)
		os.MkdirAll(tempDir, 0755)

		fmt.Printf("Update erkannt bei '%s' [%s]\n", entry.Name, entry.Platform)

		zipData, err := downloadFile(entry.URL)
		if err != nil {
			fmt.Println("Download-Fehler:", err)
			continue
		}

		extractZip(zipData, tempDir)

		if !lastRun.IsZero() {
			date := time.Now().Format("2006-01-02")
			updateDir := filepath.Join(platform, "Updates"+"_"+date, name)
			os.MkdirAll(updateDir, 0755)

			newFiles, newFQDNs := copyNewDomains(tempDir, domainDir, updateDir)
			totalNewFiles += newFiles
			totalNewFQDNs += newFQDNs
		}

		fileCount, fqdnCount := countDomainsAndFQDNs(tempDir)
		totalFiles += fileCount
		totalFQDNs += fqdnCount

		updatedPrograms++
		totalPrograms++

		os.RemoveAll(domainDir)
		os.Rename(tempDir, domainDir)
	}

	os.WriteFile(lastRunFile, []byte(time.Now().Format(time.RFC3339)), 0644)

	// Statistik
	fmt.Println("──────────────────────────────")
	fmt.Printf("Verarbeitete Programme:          %d\n", totalPrograms)
	fmt.Printf("Programme mit Updates:           %d\n", updatedPrograms)
	fmt.Printf("Second-Level Domains (Dateien):  %d\n", totalFiles)
	fmt.Printf("FQDNs insgesamt (Zeilen):        %d\n", totalFQDNs)
	fmt.Printf("Neue Dateien (Updates):          %d\n", totalNewFiles)
	fmt.Printf("Neue FQDNs (Updates):            %d\n", totalNewFQDNs)
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
		fmt.Println("Fehler beim Entpacken:", err)
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

	filepath.WalkDir(newDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(newDir, path)
		oldPath := filepath.Join(oldDir, relPath)

		if _, err := os.Stat(oldPath); os.IsNotExist(err) {
			destPath := filepath.Join(updateDir, relPath)
			os.MkdirAll(filepath.Dir(destPath), 0755)
			copyFile(path, destPath)
			newFileCount++
			fqdnLines, _ := countLines(path)
			newFQDNCount += fqdnLines
		}

		return nil
	})

	return newFileCount, newFQDNCount
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
