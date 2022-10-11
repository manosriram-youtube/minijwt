# minijwt

### Build and Run
1. `go build main.go`
2. `./main --help`

## Sign Token
```
./main sign --payload="{\"name\": \"minijwt\"}" --secret=somesecret
```

## Verify Token
```
./main verify --token=bWFwW2FsZ29yaXRobTpBRVMgdHlwZTptaW5pand0XQ.eyJlYXQiOiIxNjY1NTI2ODg3IiwibmFtZSI6Im1hbm8ifQ.wqsfHUbQbaRHyGYdcXL5ybJ7NMhLSmhVbX4r1TiFTwnPe9eki4EG1IyluZS6lOdjGZZdSXmoeWNj/lfwAbVSfU9o3dFpJJ3HYqrVyfva0vjg5dJN7yIrewYBfASL5TQurmcMjeI+F/+G --secret=somesecret
```

## Help
```./main --help```
