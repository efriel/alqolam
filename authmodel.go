package main

import (
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

//ErrorResponse structure for to accept Error Code and Error Message
type ErrorResponse struct {
	Code    int
	Message string
}

//SuccessResponse structure to accept Success Response Code and message
type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

//Claims mean structure for name email from payload
type Claims struct {
	Name   string
	Email  string
	Id int	
	jwt.StandardClaims
}

//RegistrationParams structure for name email and password
type RegistrationParams struct {	
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

//LoginParams structure for email and password for the login form request
type LoginParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

//SuccessfulLoginResponse structure for Name, email and Token
type SuccessfulLoginResponse struct {
	Name         string `json:"name" bson:"name"`
	Email        string `json:"email" bson:"email"`
	AuthToken    string	
	Id       int `json:"id" bson:"id"`	
	Dob	string `json:"dob" bson:"dob"`
	Address string `json:"address" bson:"address"`
	Description string `json:"description" bson:"description"`
	CreatedAt time.Time	
}

//NormalErrorResponse to returning normal error message
type NormalErrorResponse struct {
	Title       string
	Description string
}

//UserDetails structure for user detail
type UserDetails struct {
	Name     string `json:"name" bson:"name"`
	Email    string	
	Password string `json:"password" bson:"password"`
	Id   int `json:"id" bson:"id"`	
	Dob	string `json:"dob" bson:"dob"`
	Address string `json:"address" bson:"address"`
	Description string `json:"description" bson:"description"`
	CreatedAt time.Time	`json:"CreatedAt" bson:"CreatedAt"`
}


//CompleteUserDetails is a completed version of user detail
type CompleteUserDetails struct {
	Name     string `json:"name" bson:"name"`
	Email    string `json:"email" bson:"email"`
	Id   int `json:"id" bson:"id"`	
	Dob	string `json:"dob" bson:"dob"`
	Address string `json:"address" bson:"address"`
	Description string `json:"description" bson:"description"`
	CreatedAt time.Time	`json:"CreatedAt" bson:"CreatedAt"`
}

//SuccessResponsDataTable return to datatable
type SuccessResponsDataTable struct {		
	RecordsTotal int64 `json:"recordsTotal"`
	RecordsFiltered int64 `json:"recordsFiltered"`
	Draw int `json:"draw"`
	Data interface{} `json:"data"`
}									