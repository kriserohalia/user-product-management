package authcontroller

import (
	"user-product-management/config"
	"time"
	"gorm.io/gorm"
	"user-product-management/helper"
	"user-product-management/models"
	"encoding/json"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
)

func Login(w http.ResponseWriter, r * http.Request){
	//mengambil inputan json

	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		response:= map[string]string{"message" :err.Error()}
		helper.ResponseJson(w, http.StatusBadRequest, response)
		return
	}
	defer r.Body.Close()

	// mengambil data user berdasarkan username
	var user models.User
	if err := models.DB.Where("username = ?", userInput.Username).First(&user).Error;err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			response:=map[string]string{"message":"username atau password salah "}
			helper.ResponseJson(w, http.StatusUnauthorized, response)
			return

		default:
			response := map[string]string{"message":err.Error()}
			helper.ResponseJson(w, http.StatusInternalServerError, response)
			return
		}
	}

	//cek password valid
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password)); err != nil {
		response:= map[string]string{"message":"username atau password salah"}
		helper.ResponseJson(w, http.StatusUnauthorized, response)
		return
	}

	//membuat token jwt
	expTime:=time.Now().Add(time.Minute * 1)
	claims := &config.JWTClaim{
		Username:user.Username,
		RegisteredClaims:jwt.RegisteredClaims{
			Issuer : "go-jwt-mux",
			ExpiresAt :jwt.NewNumericDate(expTime),
		},
	}

	// algoritma yang akan digunakan
	tokenAlgo := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//signed token
	token, err := tokenAlgo.SignedString(config.JWT_KEY)
	if err != nil {
		response := map[string]string{"message":err.Error()}
		helper.ResponseJson(w, http.StatusInternalServerError, response)
		return
	}

	//set token ke cookie
	http.SetCookie(w, &http.Cookie{
		Name:"token",
		Path:"/",
		Value:token,
		HttpOnly:true,
	})

	response:= map[string]string{"message":"login berhasil"}
	helper.ResponseJson(w, http.StatusOK, response)
}

func Register(w http.ResponseWriter, r *http.Request){
	// mengambil inputan json
	var userInput models.User
	decoder:= json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err !=nil {
		response := map[string]string{"message":err.Error()}
		helper.ResponseJson(w, http.StatusBadRequest, response)
		return
	}
	defer r.Body.Close()

	//hash pass menggunakan bcrypt
	hashPassword, _:= bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
	userInput.Password = string(hashPassword)

	//insert ke database 
	if err := models.DB.Create(&userInput).Error; err != nil {
		response:= map[string]string{"message":err.Error()}
		helper.ResponseJson(w, http.StatusInternalServerError, response)
		return
	}

	response := map[string]string{"message":"success"}
	helper.ResponseJson(w, http.StatusOK, response)

}

func Logout(w http.ResponseWriter, r *http.Request){
	//hapus token yang ada di cookie
	http.SetCookie(w, &http.Cookie{
		Name:"Token",
		Path:"/",
		Value:"",
		HttpOnly:true,
		MaxAge:-1,
	})

	response := map[string]string{"message":"anda telah logout"}
	helper.ResponseJson(w, http.StatusOK, response)
}