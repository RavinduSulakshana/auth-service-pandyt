package main

import (
	"log"

	"github.com/RavinduSulakshana/auth-service-pandyt/database"
	"github.com/RavinduSulakshana/auth-service-pandyt/utils"
	"github.com/ccojocar/zxcvbn-go/data"
)

func main(){
	//Load config
	config :=utils.LoadConfig()

	//Initialize database
	db,err:=database.New(config.DBPath)
	if err != nil {
		log.Fatal("Failed to Initialize database:",err)
	}
	defer.db.Close()

	//Initialize JWT manager
	jwtManager
}
