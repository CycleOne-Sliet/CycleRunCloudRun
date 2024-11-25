package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

var app *firebase.App

var db *firestore.Client

var ctx context.Context

var authClient *auth.Client

var seecret = os.Getenv("SEECRET")

var key = make([]byte, 16)

var keyCipher cipher.Block

func main() {
	ctx = context.Background()
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("error initilizing firebase app: %v\n", err)
	}
	db, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("Failed to initialise connection to Firestore: %v\n", err)
	}
	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatalf("Failed to initialise connection to Firebase Auth: %v\n", err)
	}
	_, err = base64.StdEncoding.Decode(key, []byte(seecret))
	if err != nil {
		log.Fatal("Error while decoding key")
	}
	keyCipher, err = aes.NewCipher(key)
	if err != nil {
		log.Fatal("Error while parsing key")
	}
	log.Print("Starting server")
	http.HandleFunc("/get_token", sendTriggerToken)
	http.HandleFunc("/update_data", recieveTriggerToken)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}
	log.Printf("Listening on port %s", port)
	log.Printf("Running now")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func verifyFirebaseAuth(r *http.Request) (string, error) {
	idToken := strings.TrimSpace(strings.Replace(r.Header.Get("Authorization"), "Bearer", "", 1))
	if idToken == "" {
		return "", errors.New("No Bearer Token")
	}
	token, err := authClient.VerifyIDTokenAndCheckRevoked(ctx, idToken)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error while verifying token: %v", err))
	}
	return token.UID, nil
}

type User struct {
	CycleOccupied int  `firebase:"CycleOccupied"`
	Strikes       int  `firebase:"Strikes"`
	HasCycle      bool `firebase:"HasCycle"`
}

type Stand struct {
	Cycle    int    `firebase:"Cycle"`
	HasCycle bool   `firebase:"HasCycle"`
	Photo    string `firebase:"Photo"`
}

type Cycle struct {
	IsUnlocked bool   `firebase:"IsUnlocked"`
	Tag        string `firebase:"Tag"`
}

type JournalEntry struct {
	EntryTime  time.Time              `firebase:"EntryTime"`
	Type       string                 `firebase:"Type"`
	Stand      *firestore.DocumentRef `firebase:"Stand"`
	IsUnlocked bool                   `firebase:"IsUnlocked"`
	By         *firestore.DocumentRef `firebase:"By"`
}

func sendTriggerToken(w http.ResponseWriter, r *http.Request) {
	uid, err := verifyFirebaseAuth(r)
	if err != nil {
		log.Printf("Error while parsing Auth Token: %v\n", err)
		w.WriteHeader(401)
		fmt.Fprintf(w, "User is unauthorized")
		return
	}
	userSnap, err := db.Collection("users").Doc(uid).Get(ctx)

	if err != nil {
		log.Printf("Error while parsing getting info about user: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while parsing getting info about user")
		return
	}

	var user User
	userSnap.DataTo(&user)
	IV := make([]byte, 16)
	rand.Read(IV)
	encryptor := cipher.NewCBCEncrypter(keyCipher, IV)
	unencryptedResp := [16]byte{}
	rand.Read(unencryptedResp[0:8])
	if user.HasCycle {
		unencryptedResp[8] = 0
	} else {
		unencryptedResp[8] = 1
	}
	response := [40]byte{}
	for i := 0; i < 8; i++ {
		response[i] = unencryptedResp[i]
	}
	for i := 0; i < 16; i++ {
		response[i+8] = IV[i]
	}
	encryptor.CryptBlocks(response[24:], unencryptedResp[:])

	data, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error while reading the request data: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while reading the request data")
		return

	}

	macAddress, Unlocked, err := decodeResp(data)
	if err != nil {
		log.Printf("Error while reading the request data: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while reading the request data")
		return

	}
	w.Write(response[:])
	db.Collection("journal").Add(ctx, JournalEntry{EntryTime: time.Now(), Type: "Trigger", By: userSnap.Ref, Stand: db.Collection("stands").Doc(macAddress.String()), IsUnlocked: Unlocked})
}

func decodeResp(data []byte) (net.HardwareAddr, bool, error) {
	if len(data) != 40 {
		return nil, false, errors.New("Data length is not equal to 40")
	}
	decryptedResp := [16]byte{}
	decryptor := cipher.NewCBCDecrypter(keyCipher, data[8:24])
	decryptor.CryptBlocks(decryptedResp[:], data[24:])
	valid := true
	for i := 0; i < 8; i++ {
		if decryptedResp[i] != data[i] {
			valid = false
			break
		}
	}
	if !valid {
		return nil, false, errors.New("Verification id mismatch")
	}
	isStandUnlocked := decryptedResp[8] == 1
	macAddressBytes := decryptedResp[9:15]
	macAddress := net.HardwareAddr(macAddressBytes)
	return macAddress, isStandUnlocked, nil
}

func recieveTriggerToken(w http.ResponseWriter, r *http.Request) {
	uid, err := verifyFirebaseAuth(r)
	if err != nil {
		log.Printf("Error while parsing Auth Token: %v\n", err)
		w.WriteHeader(401)
		fmt.Fprintf(w, "User is unauthorized")
		return
	}
	userSnap, err := db.Collection("users").Doc(uid).Get(ctx)
	if err != nil {
		log.Printf("Error while parsing info about user: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while getting info about user")
		return
	}
	var user User
	userSnap.DataTo(&user)
	resp, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error while parsing the body: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while parsing the body")
		return
	}
	if len(resp) != 40 {
		log.Printf("Error while parsing the body: %s\n", "length is not equal to 40")
		w.WriteHeader(500)
		fmt.Fprintf(w, "Error while parsing the body")
		return
	}

	macAddress, isStandUnlocked, err := decodeResp(resp)

	db.Collection("journal").Add(ctx, JournalEntry{EntryTime: time.Now(), Type: "Response", By: userSnap.Ref, Stand: db.Collection("stands").Doc(macAddress.String()), IsUnlocked: isStandUnlocked})
	standSnap, err := db.Collection("stands").Doc(macAddress.String()).Get(ctx)
	var stand Stand
	standSnap.DataTo(&stand)
	user.HasCycle = isStandUnlocked
	user.CycleOccupied = stand.Cycle
	stand.Cycle = -1
	userSnap.Ref.Set(ctx, user)
	standSnap.Ref.Set(ctx, stand)
	log.Println("Successfully updated user and stand")
	fmt.Fprintf(w, "Success")
}
