package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of druk",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("druk version 0.1.0-alpha")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
