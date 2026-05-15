test:
	go test ./... -coverpkg=./... -cover

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run

