package models

type Product struct {
	Id int64 `gorm:"primaryKey" json:"id"`
	Nama string `gorm:"type:varchar(255)" json:"nama"`
	Deskripsi string `gorm:"type:varchar(255)" json:"deskripsi"`
	Harga float64 `gorm:"type:decimal(14,2)" json:"harga"`
	Stok int32 `gorm:"type:int(5)" json:"stok"`
	
}