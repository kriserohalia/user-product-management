package main


import (
	"user-product-management/middlewares"
	"user-product-management/controllers/productcontroller"
	"user-product-management/models"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"user-product-management/controllers/authcontroller"
)

func main() {
	models.ConnectDB()
	r := mux.NewRouter()
	r.HandleFunc("/login", authcontroller.Login).Methods("POST")
	r.HandleFunc("/register", authcontroller.Register).Methods("POST")
	r.HandleFunc("/logout", authcontroller.Logout).Methods("GET")

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/products", productcontroller.Index).Methods("GET")
	api.HandleFunc("/product/{id}", productcontroller.Show).Methods("GET")
	api.HandleFunc("/product", productcontroller.Create).Methods("POST")
	api.HandleFunc("/product/{id}", productcontroller.Update).Methods("PUT")
	api.HandleFunc("/product", productcontroller.Delete).Methods("DELETE")


	api.Use(middlewares.JWTMiddleware)

	log.Fatal(http.ListenAndServe(":8088", r))

}
