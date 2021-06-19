package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"	
)

var httpClient = &http.Client{}

//ViewUser to show all product
func ViewUser(response http.ResponseWriter, request *http.Request) {
	//var results ResultForm	
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}

	collection := Client.Database("alqolamdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)		
	showInfoCursor, err := collection.Find(context.TODO(), bson.M{})	
	results := []bson.M{}		
	if err = showInfoCursor.All(ctx, &results); err != nil {
		panic(err)
	}	
	defer cancel()	

	if err != nil {
		errorResponse.Message = "Document not found"
		returnErrorResponse(response, request, errorResponse)
	} else {		

		var successResponse = SuccessResponse{
			Code:     http.StatusOK,
			Message:  "Success",
			Response: results,
		}

		successJSONResponse, jsonError := json.Marshal(successResponse)

		if jsonError != nil {
			returnErrorResponse(response, request, errorResponse)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Write(successJSONResponse)
	}
}	


//UpdateUser to save UpdateUser
func UpdateUser(response http.ResponseWriter, request *http.Request) {		
	var NewupdateUser CompleteUserDetails
	vars := mux.Vars(request)
	Userid := vars["id"]
	fmt.Printf("%v\n", Userid)
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}

	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&NewupdateUser)

	defer request.Body.Close()

	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {		
		collection := Client.Database("alqolamdb").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		NewupdateUser = CompleteUserDetails{				
			Name:     NewupdateUser.Name,
			Email:    NewupdateUser.Email,				
			Dob:    NewupdateUser.Dob,		
			Description:    NewupdateUser.Description,		
			Address:    NewupdateUser.Address,		
			CreatedAt:    NewupdateUser.CreatedAt,
		}
		_, err := collection.UpdateOne(
			ctx,
			bson.M{"id": Userid},
			bson.M{
				"$set": bson.M{
					"name":    NewupdateUser.Name,					
					"dob":    NewupdateUser.Dob,
					"description":    NewupdateUser.Description,
					"address":  NewupdateUser.Address,
					"CreatedAt":    NewupdateUser.CreatedAt,						
				},
			},
		)

		defer cancel()		
		if err != nil {
			errorResponse.Message = "Document not found"
			returnErrorResponse(response, request, errorResponse)
		} else {
			var successResponse = SuccessResponse{
				Code:     http.StatusOK,
				Message:  "Success",
				Response: NewupdateUser,
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Write(successJSONResponse)
		}

	}
}


//EmailValidation for check email in the mongodb
func EmailValidation(email string) bool {
	var results CompleteUserDetails
	collection := Client.Database("alqolamdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var err = collection.FindOne(ctx, bson.M{
		"email": email,
	}).Decode(&results)
	defer cancel()
	if err != nil {
		return false
	} else {
		return true
	}
}

//SignInUser to accept request from user login
func SignInUser(response http.ResponseWriter, request *http.Request) {
	var loginRequest LoginParams
	var successResponse SuccessResponse
	var result UserDetails
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}

	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&loginRequest)
	fmt.Println(fmt.Sprintf("%#v", loginRequest))
	defer request.Body.Close()

	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {
		//errorResponse.Code = http.StatusBadRequest
		successResponse = SuccessResponse{
			Code:    http.StatusLengthRequired,
			Message: "Failed",
			Response: NormalErrorResponse{
				Title:       "password",
				Description: "Email and Password are Empty",
			},
		}

		if loginRequest.Email == "" {
			successResponse = SuccessResponse{
				Code:    http.StatusLengthRequired,
				Message: "Failed",
				Response: NormalErrorResponse{
					Title:       "email",
					Description: "Email is Empty",
				},
			}

		} else if loginRequest.Password == "" {
			successResponse = SuccessResponse{
				Code:    http.StatusLengthRequired,
				Message: "Failed",
				Response: NormalErrorResponse{
					Title:       "password",
					Description: "Password is Empty",
				},
			}

		} else {

			collection := Client.Database("alqolamdb").Collection("users")			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)			
			var err = collection.FindOne(ctx, bson.M{
				"email": loginRequest.Email,
			}).Decode(&result)
			fmt.Println(fmt.Sprintf("%#v", err))											
			defer cancel()

			if err != nil {
				successResponse = SuccessResponse{
					Code:    http.StatusNotFound,
					Message: "Failed",
					Response: NormalErrorResponse{
						Title:       "email",
						Description: "Email not Found",
					},
				}

			} else {
				pwdmatch := CheckPasswordHash(loginRequest.Password, result.Password)
				if pwdmatch != true {
					successResponse = SuccessResponse{
						Code:    http.StatusUnauthorized,
						Message: "Failed",
						Response: NormalErrorResponse{
							Title:       "password",
							Description: "Password not match",
						},
					}

				} else {					
					tokenString, _ := CreateJWT(result.Name, result.Email, result.Id)					
					
					if tokenString == "" {
						returnErrorResponse(response, request, errorResponse)
					}

					successResponse = SuccessResponse{
						Code:    http.StatusOK,
						Message: "Success",
						Response: SuccessfulLoginResponse{
							Name:      result.Name,
							Email:     result.Email,
							AuthToken: tokenString,							
							Id:    result.Id,
							Dob:    result.Dob,
							Address:    result.Address,
							Description:    result.Description,
							CreatedAt:    result.CreatedAt,
						},
					}

				}
			}
		}
		successJSONResponse, jsonError := json.Marshal(successResponse)
		response.Header().Set("Content-Type", "application/json")
		response.Write(successJSONResponse)

		if jsonError != nil {
			returnErrorResponse(response, request, errorResponse)
		}
	}
}

//SignUpUser to accept request from user signup
func SignUpUser(response http.ResponseWriter, request *http.Request) {
	var registrationRequest RegistrationParams
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}
	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&registrationRequest)
	defer request.Body.Close()

	if decoderErr != nil {
		errorResponse.Code = 200
		errorResponse.Message = "Failed to Signup."
		returnErrorResponse(response, request, errorResponse)
	} else {
		errorResponse.Code = http.StatusBadRequest
		fmt.Printf(registrationRequest.Email)
		if registrationRequest.Name == "" {
			errorResponse.Code = 200
			errorResponse.Message = "Name can't be empty"
			returnErrorResponse(response, request, errorResponse)
		} else if registrationRequest.Email == "" {
			errorResponse.Code = 200
			errorResponse.Message = "Email can't be empty"
			returnErrorResponse(response, request, errorResponse)
		} else if registrationRequest.Password == "" {
			errorResponse.Code = 200
			errorResponse.Message = "Password can't be empty"
			returnErrorResponse(response, request, errorResponse)
		} else {
			tnow := time.Now()
			tsec := tnow.Unix()
			ntsec := strconv.FormatInt(tsec, 10)
			ntsecint, _ := strconv.Atoi(ntsec)			

			now := time.Now()			
			tokenString, _ := CreateJWT(registrationRequest.Name, registrationRequest.Email, ntsecint)

			if tokenString == "" {
				returnErrorResponse(response, request, errorResponse)
			}

			var registrationResponse = SuccessfulLoginResponse{												
				Name:      registrationRequest.Name,
				Email:     registrationRequest.Email,
				AuthToken: tokenString,							
				Id:    ntsecint,				
				CreatedAt:    now,
			}

			collection := Client.Database("alqolamdb").Collection("users")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, databaseErr := collection.InsertOne(ctx, bson.M{				
				"name":     registrationRequest.Name,
				"email":    registrationRequest.Email,
				"id":  ntsecint,
				"password": getHash([]byte(registrationRequest.Password)),				
				"CreatedAt": now,
			})
			defer cancel()

			if databaseErr != nil {
				returnErrorResponse(response, request, errorResponse)
			}

			var successResponse = SuccessResponse{
				Code:     http.StatusOK,
				Message:  "Successfully registered, login again",
				Response: registrationResponse,
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(successResponse.Code)
			response.Write(successJSONResponse)
		}
	}
}

//GetUserDetails to accept request for user detail
func GetUserDetails(response http.ResponseWriter, request *http.Request) {
	var result UserDetails
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}
	bearerToken := request.Header.Get("Authorization")
	var authorizationToken = strings.Split(bearerToken, " ")[1]

	email, _ := VerifyToken(authorizationToken)
	if email == "" {
		returnErrorResponse(response, request, errorResponse)
	} else {
		collection := Client.Database("alqolamdb").Collection("users")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err = collection.FindOne(ctx, bson.M{
			"email": email,
		}).Decode(&result)
		//result := []bson.M{}
		fmt.Printf("%v\n", result)
		defer cancel()

		if err != nil {
			returnErrorResponse(response, request, errorResponse)
		} else {
			var successResponse = SuccessResponse{
				Code:     http.StatusOK,
				Message:  "Successfully logged in ",
				Response: result,
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Write(successJSONResponse)
		}
	}
}

//GetCompleteUserDetails to accept request for user detail
func GetCompleteUserDetails(response http.ResponseWriter, request *http.Request) {
	var results CompleteUserDetails
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Internal Server Error.",
	}
	bearerToken := request.Header.Get("Authorization")
	var authorizationToken = strings.Split(bearerToken, " ")[1]

	email, _ := VerifyToken(authorizationToken)

	if email == "" {
		returnErrorResponse(response, request, errorResponse)
	} else {
		collection := Client.Database("alqolamdb").Collection("users")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err = collection.FindOne(ctx, bson.M{
			"email": email,
		}).Decode(&results)

		defer cancel()
		fmt.Printf("%v\n", results)

		if err != nil {
			errorResponse.Message = "User not found"
			returnErrorResponse(response, request, errorResponse)
		} else {
			var successResponse = SuccessResponse{
				Code:     http.StatusOK,
				Message:  "Success",
				Response: results,
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Write(successJSONResponse)
		}

	}
}

//returnErrorResponse to returne response code from server
func returnErrorResponse(response http.ResponseWriter, request *http.Request, errorMesage ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMesage.Code, Message: errorMesage.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(errorMesage.Code)
	response.Write(jsonResponse)
}

//getHash to get hash from current password
func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

//CheckPasswordHash to compare password in db
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
