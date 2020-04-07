package app

import (
	"../models"
	"../utils"
	"context"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"os"
	"strings"
)

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request){

		notAuth := []string{"/api/user/new","api/user/login"} // list of End points that doesn't require auth
		requestPath := r.URL.Path // current request path

		//check if request does not need authetication, serve the request if it doesn't need it
		for _,value := range notAuth {
			if value == requestPath{
				next.ServeHTTP(w,r)
				return
			}
		}

		response := make(map[string] interface{})
		tokenHeader := r.Header.Get("Authorization") // Grab the token from the header

		if tokenHeader == ""{ // tokes is missing, returns with error code 403 Unauthorized
			response = utils.Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type","application/json")
			utils.Respond(w, response)
			return
		}
		//The token normally comes in format Bearer {token-body}
		//we check if the the retrieved token matched this requirement
		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			response = utils.Message(false, "Invalid/Malformed auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w,response)
			return
		}

		tokenPart := splitted[1]
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil { // Malformed token
			response = utils.Message(false,"Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w,response)
			return
		}

		if !token.Valid{ // token is invalid, maybe not signed on this server
			response = utils.Message(false,"Token is not valid")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w,response)
			return
		}

		//Everything went well, proceed with the request and set caller to the user retrieved from the parsed token
		//fmt.Sprintf("User %", tk.Username) // useful for monitoring
		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
	})
}