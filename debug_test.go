package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Just check if we can create files in tmpDir
	tmpDir := "D:/tmp/kvtest2"

	err := os.MkdirAll(tmpDir, 0755)
	if err != nil {
		fmt.Printf("MkdirAll failed: %v\n", err)
		return
	}

	// Create a test file
	f, err := os.Create(filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		fmt.Printf("Create failed: %v\n", err)
		return
	}
	f.Close()

	// Check what files exist
	files, _ := os.ReadDir(tmpDir)
	fmt.Printf("Files in %s: %v\n", tmpDir, files)

	// Now check what tmpDir actually points to on Windows
	fmt.Printf("TMPDIR: %s\n", os.Getenv("TMPDIR"))
	fmt.Printf("TMP: %s\n", os.Getenv("TMP"))
	fmt.Printf("TEMP: %s\n", os.Getenv("TEMP"))
}