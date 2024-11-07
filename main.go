package main

import (
	"jwt-teestProject/auth"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/register", auth.RegisterHandler)
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/protected", auth.JWTMiddleware(auth.ProtectedHandler))

	log.Println("Server running on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err.Error())
	}
}
