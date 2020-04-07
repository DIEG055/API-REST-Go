
package main

import (
	"./app"
	"./controllers"
	"./models"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)

func main() {
	//models.Init()
	defer models.GetDB().Close()
	router := mux.NewRouter() // we start listening for incoming requests
	router.Use(app.JwtAuthentication) //attach JWT auth middleware
	router.HandleFunc("/api/user/new", controllers.CreateAccount).Methods("POST")
	router.HandleFunc("/api/user/login", controllers.Authenticate).Methods("POST")
	//router.HandleFunc("/api/me/contacts", controllers.GetContactsFor).Methods("GET")

	port := os.Getenv("PORT") //Get port from .env file, we did not specify any port so this should return an empty string when tested locally
	if port == "" {
		port = "8000" //localhost
	}

	fmt.Println(port)

	err := http.ListenAndServe(":" + port, router) //Launch the app, visit localhost:8000/api
	if err != nil {
		fmt.Print(err)
	}
}