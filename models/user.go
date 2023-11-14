package models

type User struct {
	Id int64 `gorm:"primaryKey" json:"id"`
	NamaLengkap string `grom:"varchar(255)" json:"nama_lengkap"`
	Username string `gorm:"varchar(255)" json:"username"`
	Password string `gorm:"varchar(255)" json:"passowrd"`
}