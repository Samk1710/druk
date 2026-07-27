package main

import (
	"github.com/joho/godotenv"
	"github.com/samk/druk/cmd"
)

func main() {
	_ = godotenv.Load() // Ignore error if .env doesn't exist
	cmd.Execute()
}
