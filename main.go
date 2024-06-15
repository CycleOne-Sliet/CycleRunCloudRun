package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	http.HandleFunc("/get_token", getToken)
	http.HandleFunc("/update_data", updateData)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
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
	CycleOccupied *firestore.DocumentRef `firebase:"cycleOccupied"`
	HasCycle      bool                   `firebase:"hasCycle"`
}

type UnlockRequest struct {
	Cycle      *firestore.DocumentRef `firebase:"cycleId"`
	MadeAtTime time.Time              `firebase:"madeAtTime"`
	MadeBy     *firestore.DocumentRef `firebase:"madeBy"`
	TookFrom   *firestore.DocumentRef `firebase:"tookFrom"`
	ReturnedAt time.Time              `firebase:"returnedAt"`
	ReturnedTo *firestore.DocumentRef `firebase:"returnedTo"`
}

type Stand struct {
	Cycle *firestore.DocumentRef `firebase:"cycle"`
	photo string                 `firebase:"photo"`
}

type StandLocation struct {
	Stands   []*firestore.DocumentRef `firebase:"stands"`
	Location string                   `firebase:"location"`
	photo    string                   `firebase:"photo"`
}

type Cycle struct {
	IsUnlocked bool   `firebase:"isUnlocked"`
	Tag        string `firebase:"tag"`
}

type RequestToken struct {
	IsUnlocked bool   `json:"isUnlocked"`
	CycleId    string `json:"cycleId"`
	StandTime  uint64 `json:"time"`
	Mac        string `json:"mac"`
}

func getToken(w http.ResponseWriter, r *http.Request) {
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
	if user.HasCycle {
		log.Print("User already has a cycle")
		w.WriteHeader(401)
		fmt.Fprintf(w, "User already has a cycle")
		return
	}
	IV := make([]byte, 16)
	rand.Read(IV)
	tokenB64, err := io.ReadAll(r.Body)
	unparsedToken := make([]byte, len(tokenB64)/4+8)
	unparsedTokenLen, err := base64.StdEncoding.Decode(unparsedToken, tokenB64)
	if err != nil {
		log.Printf("Error while parsing token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}

	encryptor := cipher.NewCBCEncrypter(keyCipher, IV)
	decryptor := cipher.NewCBCDecrypter(keyCipher, unparsedToken[:16])
	jsonString := make([]byte, unparsedTokenLen)
	decryptor.CryptBlocks(jsonString, unparsedToken[16:])
	var token RequestToken
	err = json.Unmarshal(jsonString, &token)
	if err != nil {
		log.Printf("Error while decoding token json: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}
	current_time := time.Now()
	cycleRef := db.Collection("cycles").Doc(token.CycleId)
	standRef := db.Collection("stands").Doc(token.Mac)
	userRef := db.Collection("users").Doc(uid)
	unlockReqCollection := db.Collection("unlockRequests")
	var stand Stand
	stand.Cycle = nil
	if err = db.RunTransaction(ctx, func(ctx context.Context, transaction *firestore.Transaction) error {
		if _, err = standRef.Set(ctx, stand); err != nil {
			return err
		}
		if _, _, err = unlockReqCollection.Add(ctx, UnlockRequest{
			Cycle:      cycleRef,
			MadeAtTime: current_time,
			TookFrom:   standRef,
			MadeBy:     userRef,
		}); err != nil {
			return err
		}
		userRef.Set(ctx, User{HasCycle: true, CycleOccupied: cycleRef})
		return nil
	}); err != nil {
		log.Printf("Error while running transaction: %v\n", err)
		w.WriteHeader(500)
		fmt.Fprintf(w, "Internal error")
		return
	}
	unencryptedResp := []byte(fmt.Sprintf("%s:%s:%d;", uid, token.CycleId, current_time.Unix()))
	unencryptedRespLen := len(unencryptedResp)
	unencryptedResp = append(unencryptedResp, make([]byte, encryptor.BlockSize()-len(unencryptedResp)%encryptor.BlockSize())...)
	for i := unencryptedRespLen; i < len(unencryptedResp); i++ {
		unencryptedResp[i] = 0
	}
	response := make([]byte, len(unencryptedResp))
	encryptor.CryptBlocks(response, unencryptedResp)
	response = append(IV, response...)
	w.Write(response)
}

func updateData(w http.ResponseWriter, r *http.Request) {
	tokenB64, err := io.ReadAll(r.Body)
	unparsedToken := make([]byte, len(tokenB64)/4+8)
	unparsedTokenLen, err := base64.StdEncoding.Decode(unparsedToken, tokenB64)
	if err != nil {
		log.Printf("Error while parsing token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}

	decryptor := cipher.NewCBCDecrypter(keyCipher, unparsedToken[:16])
	jsonString := make([]byte, unparsedTokenLen)
	decryptor.CryptBlocks(jsonString, unparsedToken[16:])
	var token RequestToken
	err = json.Unmarshal(jsonString, &token)
	if err != nil {
		log.Printf("Error while decoding token json: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}
	current_time := time.Now()
	if token.IsUnlocked {
		cycleRef := db.Collection("cycles").Doc(token.CycleId)
		docs := db.Collection("unlockRequests").Where("cycleId", "==", cycleRef).Documents(ctx)
		standRef := db.Collection("stands").Doc(token.Mac)
		standDoc, err := standRef.Get(ctx)
		if err != nil {
			log.Printf("Error while getting a stand reference: %v\n", err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "Error while getting stand")
			return
		}
		var stand Stand

		standDoc.DataTo(&stand)
		stand.Cycle = cycleRef
		batch := db.BulkWriter(ctx)
		batch.Set(standRef, stand)
		for d, err := docs.Next(); d != nil; d, err = docs.Next() {
			if err != nil {
				log.Printf("Error while getting a unlock request: %v\n", err)
				w.WriteHeader(500)
				fmt.Fprintf(w, "Error while getting unlock request")
				return
			}
			var request UnlockRequest
			d.DataTo(&request)
			request.ReturnedAt = current_time
			request.ReturnedTo = standRef
			batch.Set(d.Ref, request)
		}
		batch.End()
	}
}
