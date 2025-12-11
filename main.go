package main

import (
	"log"

	"github.com/aspnmy/chatlog/cmd/chatlog"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	chatlog.Execute()
}
