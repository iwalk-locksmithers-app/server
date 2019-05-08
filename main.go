package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type AuthURL struct {
	AuthURL string
}

type LoginData struct {
	Seed     string
	Password string
}

type AuthResponse struct {
	IsValid bool
	LockURL string
	Time    time.Duration
}

func notFound(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Page not found")
}

func getAuthURL(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	url := "/auth/v2"

	if userAgent == "ed9ae2c0-9b15-4556-a393-23d500675d4b" {
		url = "/auth/v1_1"
	}

	resp := AuthURL{AuthURL: url}
	w.Header().Set("Server", "iWalk-Server-v2")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

//iWalk-Locks: Production auth
func v2Auth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	decoder := json.NewDecoder(r.Body)
	var loginData LoginData
	err := decoder.Decode(&loginData)
	if err != nil {
		ret := getResponseToken(start, false, "")
		returnToken(w, ret)
		return
	}

	//LockSmiter: better Auth checks for our app
	for _, lock := range getLocks() {
		if lock.Password == loginData.Password && lock.Seed == loginData.Seed {
			ret := getResponseToken(start, true, lock.Value)
			returnToken(w, ret)
			return
		}
	}

	ret := getResponseToken(start, false, "")
	returnToken(w, ret)
}

//iWalk-Locks: old auth, depcrated developed by OG
//that is no longer with us
//TODO: deprecated, remove from code
func v1Auth(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "ed9ae2c0-9b15-4556-a393-23d500675d4b" {
		returnServerError(w, r)
		return
	}

	start := time.Now()

	decoder := json.NewDecoder(r.Body)
	var loginData LoginData
	err := decoder.Decode(&loginData)
	if err != nil {
		ret := getResponseToken(start, false, "")
		returnToken(w, ret)
		return
	}

	for _, lock := range getLocks() {
		if loginData.Seed != lock.Seed {
			continue
		}

		currentIndex := 0
		for currentIndex < len(lock.Password) && currentIndex < len(loginData.Password) {
			if lock.Password[currentIndex] != loginData.Password[currentIndex] {
				break
			}
			//OG: securing against bruteforce attempts... ;-)
			time.Sleep(30 * time.Millisecond)
			currentIndex++
		}

		if currentIndex == len(lock.Password) {
			ret := getResponseToken(start, true, lock.Value)
			returnToken(w, ret)
			return
		}
	}

	ret := getResponseToken(start, false, "")
	returnToken(w, ret)
}

func getResponseToken(from time.Time, isValid bool, lockURL string) []byte {
	elapsed := time.Since(from)
	resp := AuthResponse{IsValid: isValid, LockURL: lockURL, Time: elapsed}
	js, err := json.Marshal(resp)
	if err != nil {
		return nil
	}

	return js
}

func returnToken(w http.ResponseWriter, js []byte) {
	if js == nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Server", "iWalk-Server-v2")
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func returnServerError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "iWalk-Server-v2")
	http.Error(w, "Oh no. We might have a problem; trained monkies are on it.", http.StatusInternalServerError)
}

func main() {
	if getLocks() == nil {
		panic("Something is wrong with the locks file")
	}

	http.HandleFunc("/auth/getUrl", getAuthURL)
	http.HandleFunc("/auth/v1_1", v1Auth)
	http.HandleFunc("/auth/v2", v2Auth)
	http.HandleFunc("/", notFound)
	log.Fatal(http.ListenAndServe(":8070", nil))
}
