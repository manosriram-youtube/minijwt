package main

import "minijwt/pkg/cmd"

func main() {
	// logger, _ := zap.NewProduction()
	// defer logger.Sync() // flushes buffer, if any
	// sugar := logger.Sugar()
	// svc := minijwt.NewService(sugar)

	cmd.Execute()
	// secret := "thisis32bitlongpassphraseimusing"
	// var payload map[string]interface{}

	// payload := map[string]interface{}{
	// "name":  "jane doe",
	// "age":   23,
	// "place": "india",
	// }
	// this must be a 32 bit key

	// token, _ := svc.Sign(payload, secret)

	// originalPayload, _ := svc.Verify(token, secret)
	// fmt.Println(originalPayload)
}
