package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
	CycleOccupied *firestore.DocumentRef `firebase:"CycleOccupied"`
	HasCycle      bool                   `firebase:"HasCycle"`
}

type UnlockRequest struct {
	Cycle      *firestore.DocumentRef `firebase:"CycleId"`
	MadeAtTime time.Time              `firebase:"MadeAtTime"`
	MadeBy     *firestore.DocumentRef `firebase:"MadeBy"`
	TookFrom   *firestore.DocumentRef `firebase:"TookFrom"`
	ReturnedAt time.Time              `firebase:"ReturnedAt"`
	ReturnedTo *firestore.DocumentRef `firebase:"ReturnedTo"`
}

type Stand struct {
	Cycle *firestore.DocumentRef `firebase:"Cycle"`
	Photo string                 `firebase:"Photo"`
}

type StandLocation struct {
	Stands   []*firestore.DocumentRef `firebase:"Stands"`
	Location string                   `firebase:"Location"`
	Photo    string                   `firebase:"Photo"`
}

type Cycle struct {
	IsUnlocked bool   `firebase:"IsUnlocked"`
	Tag        string `firebase:"Tag"`
}

type RequestToken struct {
	CycleId   string  `json:"CycleId"`
	StandTime uint64  `json:"Time"`
	Mac       [6]byte `json:"Mac"`
}

func NewRequestToken(data []byte) (RequestToken, error) {
	log.Printf("Data Length = %d\n", len(data))
	reader := bytes.NewReader(data)
	cycleIdLen, err := reader.ReadByte()
	if err != nil {
		return RequestToken{}, err
	}
	log.Printf("CycleIdLen = %d\n", cycleIdLen)
	cycleIdBuilder := strings.Builder{}
	cycleIdBuilder.Grow(int(cycleIdLen))
	written, err := io.CopyN(&cycleIdBuilder, reader, int64(cycleIdLen))
	if written != int64(cycleIdLen) {
		log.Printf("Read %d bytes when reading Mac", written)
		if err != nil {
			return RequestToken{}, errors.New("Message was too short")
		}
	}
	var mac [6]byte
	n, err := reader.Read(mac[:])
	if n != 6 {
		log.Printf("Read %d bytes when reading Mac", n)
		if err != nil {
			return RequestToken{}, errors.New("Message was too short")
		}
	}
	if err != nil {
		return RequestToken{}, err
	}
	var timeBytes [8]byte
	n, err = reader.Read(timeBytes[:])
	if n != 8 {
		log.Printf("Read %d bytes when reading time", n)
		if err != nil {
			return RequestToken{}, errors.New("Message was too short")
		}
	}
	if err != nil {
		return RequestToken{}, err
	}
	respTime := binary.BigEndian.Uint64(timeBytes[:])
	return RequestToken{
		CycleId:   cycleIdBuilder.String(),
		StandTime: respTime,
		Mac:       mac,
	}, nil
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
	IV := make([]byte, 16)
	rand.Read(IV)
	tokenB64, err := io.ReadAll(r.Body)
	unparsedToken := make([]byte, base64.StdEncoding.DecodedLen(len(tokenB64)))
	log.Printf("Unparsed Token: %s\n", string(tokenB64))
	unparsedTokenLen, err := base64.StdEncoding.Decode(unparsedToken, tokenB64)
	if err != nil {
		log.Printf("Error while parsing token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}

	encryptor := cipher.NewCBCEncrypter(keyCipher, IV)
	unparsedToken = append(unparsedToken, make([]byte, encryptor.BlockSize()-len(unparsedToken)%encryptor.BlockSize())...)
	decryptor := cipher.NewCBCDecrypter(keyCipher, unparsedToken[:16])
	decryptedStandToken := make([]byte, unparsedTokenLen)
	log.Printf("Length of token: %d\n", len(unparsedToken[16:]))
	log.Printf("The decoded bytes are: %v\n", unparsedToken[16:])
	decryptor.CryptBlocks(decryptedStandToken, unparsedToken[16:])
	token, err := NewRequestToken(decryptedStandToken)
	if err != nil {
		log.Printf("Error while decoding token data: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}
	current_time := time.Now()

	userRef := db.Collection("users").Doc(uid)
	if token.CycleId == "" {
		var cycle Cycle
		err = userSnap.DataTo(&user)
		if err != nil {
			log.Printf("Error while running transaction: %v\n", err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "Internal error")
			return
		}
		cycleSnap, err := user.CycleOccupied.Get(ctx)
		if err != nil {
			log.Printf("Error while running transaction: %v\n", err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "Internal error")
			return
		}
		cycleSnap.DataTo(&cycle)
		if !user.HasCycle {
			log.Printf("User does not have any cycle %+v\n", err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "User does not have any cycle")
			return
		}
		unencryptedRespLen := len(uid) + len(token.CycleId) + 16
		unencryptedResp := make([]byte, 0, unencryptedRespLen)
		unencryptedResp = append(unencryptedResp, byte(len(uid)))
		unencryptedResp = append(unencryptedResp, byte(len(token.CycleId)))
		unencryptedResp = append(unencryptedResp, []byte(uid)...)
		unencryptedResp = append(unencryptedResp, []byte(token.CycleId)...)
		unencryptedResp = append(unencryptedResp, token.Mac[:]...)
		unencryptedResp = binary.BigEndian.AppendUint64(unencryptedResp, token.StandTime)

		unencryptedResp = append(unencryptedResp, make([]byte, encryptor.BlockSize()-len(unencryptedResp)%encryptor.BlockSize())...)
		response := make([]byte, len(unencryptedResp))
		encryptor.CryptBlocks(response, unencryptedResp)
		response = append(IV, response...)
		w.Write(response)
	}
	macString := fmt.Sprintf("%X:%X:%X:%X:%X:%X", token.Mac[0], token.Mac[1], token.Mac[2], token.Mac[3], token.Mac[4], token.Mac[5])
	cycleRef := db.Collection("cycles").Doc(token.CycleId)
	cycleRef.Create(ctx, Cycle{IsUnlocked: true, Tag: token.CycleId})
	standRef := db.Collection("stands").Doc(macString)
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
	unencryptedRespLen := len(uid) + len(token.CycleId) + 16
	unencryptedResp := make([]byte, 0, unencryptedRespLen)
	unencryptedResp = append(unencryptedResp, byte(len(uid)))
	unencryptedResp = append(unencryptedResp, byte(len(token.CycleId)))
	unencryptedResp = append(unencryptedResp, []byte(uid)...)
	unencryptedResp = append(unencryptedResp, []byte(token.CycleId)...)
	log.Printf("Mac = %+v\n", token.Mac)
	unencryptedResp = append(unencryptedResp, token.Mac[:]...)
	unencryptedResp = binary.BigEndian.AppendUint64(unencryptedResp, token.StandTime)

	unencryptedResp = append(unencryptedResp, make([]byte, encryptor.BlockSize()-len(unencryptedResp)%encryptor.BlockSize())...)
	log.Printf("len(unencryptedResp) = %d, unencryptedRespLen = %d\n", len(unencryptedResp), unencryptedRespLen)
	tempStr := make([]byte, 0, len(unencryptedResp)*2)
	for _, v := range unencryptedResp {
		tempStr = append([]byte(tempStr), fmt.Sprintf("%x", v)...)
	}
	log.Printf("unencryptedResp = %s\n", string(tempStr))
	response := make([]byte, len(unencryptedResp))
	encryptor.CryptBlocks(response, unencryptedResp)
	response = append(IV, response...)
	w.Write(response)
}

func updateData(w http.ResponseWriter, r *http.Request) {
	uid, err := verifyFirebaseAuth(r)
	if err != nil {
		log.Printf("Error while parsing Auth Token: %v\n", err)
		w.WriteHeader(401)
		fmt.Fprintf(w, "User is unauthorized")
		return
	}
	userRef := db.Collection("users").Doc(uid)
	tokenB64, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error while reading token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while reading token")
		return
	}
	unparsedToken := make([]byte, base64.StdEncoding.DecodedLen(len(tokenB64)))
	unparsedTokenLen, err := base64.StdEncoding.Decode(unparsedToken, tokenB64)
	if err != nil {
		log.Printf("Error while parsing token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}
	unparsedToken = append(unparsedToken, make([]byte, keyCipher.BlockSize()-len(unparsedToken)%keyCipher.BlockSize())...)
	decryptor := cipher.NewCBCDecrypter(keyCipher, unparsedToken[:16])
	decryptedStandResp := make([]byte, unparsedTokenLen)
	decryptor.CryptBlocks(decryptedStandResp, unparsedToken[16:])
	token, err := NewRequestToken(decryptedStandResp)
	if err != nil {
		log.Printf("Error while decoding token: %v\n", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error while parsing token")
		return
	}
	current_time := time.Now()
	cycleRef := db.Collection("cycles").Doc(token.CycleId)
	docs := db.Collection("unlockRequests").Where("CycleId", "==", cycleRef).Documents(ctx)
	macString := fmt.Sprintf("%X:%X:%X:%X:%X:%X", token.Mac[0], token.Mac[1], token.Mac[2], token.Mac[3], token.Mac[4], token.Mac[5])
	standRef := db.Collection("stands").Doc(macString)
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
	batch.Set(userRef, User{HasCycle: false, CycleOccupied: nil})
	batch.End()
	log.Printf("Successfully Locked cycle")
	w.WriteHeader(200)
	fmt.Fprintf(w, "Success")
	return
}
