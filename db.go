package main

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//Client mean var for mongoclient
var Client *mongo.Client

//ConnectDatabase to connect to the mongodb
func ConnectDatabase() {
	log.Println("DB connecting...")	
	clientOptions := options.Client().ApplyURI("mongodb://useralqolam:Passalqolam!@13.213.92.199:27017/alqolamdb")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	Client = client
	if err != nil {
		log.Fatal(err)
	}
	err = Client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("DB Connected")
}
