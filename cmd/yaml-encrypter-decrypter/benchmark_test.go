package main

import (
	"os"
	"strings"
	"testing"
)

func TestOutputBenchmarkResults(t *testing.T) {
	// Создаем тестовые данные
	results := []benchmarkResult{
		{
			Category:    "Key Derivation",
			Name:        "Argon2id",
			Operations:  1000,
			NsPerOp:     500000.0,
			BytesPerOp:  1024,
			AllocsPerOp: 10,
		},
		{
			Category:    "Key Derivation",
			Name:        "PBKDF2",
			Operations:  2000,
			NsPerOp:     250000.0,
			BytesPerOp:  512,
			AllocsPerOp: 5,
		},
		{
			Category:    "Encryption",
			Name:        "AES-256-GCM",
			Operations:  5000,
			NsPerOp:     40000.0,
			BytesPerOp:  256,
			AllocsPerOp: 3,
		},
	}

	// Создаем временный файл для вывода
	tempFile := "test_benchmark_results.md"
	defer func() { _ = os.Remove(tempFile) }() // Удаляем файл после завершения теста

	// Вызываем тестируемую функцию
	err := outputBenchmarkResults(results, tempFile)
	if err != nil {
		t.Fatalf("outputBenchmarkResults returned error: %v", err)
	}

	// Проверяем, что файл был создан
	_, err = os.Stat(tempFile)
	if os.IsNotExist(err) {
		t.Fatalf("Expected benchmark results file was not created")
	}

	// Читаем содержимое файла
	content, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("Failed to read benchmark results file: %v", err)
	}

	// Проверяем, что содержимое не пустое
	if len(content) == 0 {
		t.Errorf("Benchmark results file is empty")
	}

	// Проверяем, что файл содержит ожидаемые заголовки таблицы
	expectedHeaders := []string{
		"# Benchmark Results",
		"Generated on",
		"## Key Derivation",
		"| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |",
		"| Argon2id |",
		"| PBKDF2 |",
		"## Encryption",
		"| AES-256-GCM |",
	}

	contentStr := string(content)
	for _, header := range expectedHeaders {
		if !contains(contentStr, header) {
			t.Errorf("Expected content to contain '%s', but it doesn't", header)
		}
	}

	// Проверяем вывод без файла (на stdout)
	err = outputBenchmarkResults(results[:1], "")
	if err != nil {
		t.Fatalf("outputBenchmarkResults to stdout returned error: %v", err)
	}
}

// Вспомогательная функция для проверки содержимого строки
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
