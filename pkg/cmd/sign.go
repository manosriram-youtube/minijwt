package cmd

import (
	"encoding/json"
	"fmt"
	"minijwt/pkg/minijwt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var svc minijwt.Service

// var secret = "thisis32bitlongpassphraseimusing"

func padSecret(secret string) string {
	paddedSecret := secret
	padding := 32 - len(secret)

	if padding > 0 {
		for padding > 0 {
			paddedSecret += "a"
			padding -= 1
		}
	}
	return paddedSecret
}

var Sign string
var Payload string
var Secret string
var Token string

func init() {
	logger, _ := zap.NewProduction()
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()
	svc := minijwt.NewService(sugar)
	svc = svc

	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)

	signCmd.Flags().StringVarP(&Payload, "payload", "p", "", "payload of the token")
	signCmd.Flags().StringVarP(&Secret, "secret", "s", "", "token secret")
	signCmd.MarkFlagRequired("payload")
	signCmd.MarkFlagRequired("secret")

	verifyCmd.Flags().StringVarP(&Token, "token", "t", "", "jwt token")
	verifyCmd.Flags().StringVarP(&Secret, "secret", "s", "", "token secret")
	verifyCmd.MarkFlagRequired("token")
	verifyCmd.MarkFlagRequired("secret")

}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "signs a new token",
	Long:  "signs a new token, given the payload. Default expiry is at 1hour",
	Run: func(cmd *cobra.Command, args []string) {
		var payloadJson map[string]interface{}
		secret := padSecret(Secret)

		err := json.Unmarshal([]byte(Payload), &payloadJson)
		if err != nil {
			panic(err)
		}

		token, err := svc.Sign(payloadJson, secret)
		if err != nil {
			panic(err)
		}
		fmt.Println(token)
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verifies a token",
	Long:  "verifies token, returns the payload.",
	Run: func(cmd *cobra.Command, args []string) {
		secret := padSecret(Secret)

		payload, err := svc.Verify(Token, secret)
		if err != nil {
			panic(err)
		}
		fmt.Println(payload)
	},
}

var rootCmd = &cobra.Command{
	Use:   "minijwt",
	Short: "mini version of jsonwebtoken",
	Long:  "supports: sign and verify",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("minijwt\n")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
