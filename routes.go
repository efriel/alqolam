package main

import (
	"log"

	"github.com/gorilla/mux"
)

// AddApproutes is to handle all routes coming from the http request
func AddApproutes(route *mux.Router) {
	log.Println("Loadeding Routes...")
	route.HandleFunc("/api/users", ViewUser).Methods("GET", "OPTIONS")
	route.HandleFunc("/api/users/{user_id}", ViewUser).Methods("PUT", "OPTIONS")
	route.HandleFunc("/api/signin", SignInUser).Methods("POST", "OPTIONS")
	route.HandleFunc("/api/signup", SignUpUser).Methods("POST", "OPTIONS")		
	log.Println("Routes are Loaded.")
}
