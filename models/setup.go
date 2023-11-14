package models

import (
	"gorm.io/gorm"
	"gorm.io/driver/mysql"
)

var DB *gorm.DB

func ConnectDB() {
	db, err := gorm.Open(mysql.Open("root:@tcp(localhost:3306)/users_product_management"))
	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&User{},&Product{})

	DB = db
}
