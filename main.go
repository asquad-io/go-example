package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func main() {
	apiUrl := os.Getenv("API_URL")
	apiKey := os.Getenv("API_KEY")
	apiSecret := os.Getenv("API_SECRET")

	if len(apiUrl) == 0 {
		panic("Empty API_URL env variable")
	}
	if len(apiKey) == 0 {
		panic("Empty API_KEY env variable")
	}
	if len(apiSecret) == 0 {
		panic("Empty API_SECRET env variable")
	}

	body := []byte(fmt.Sprintf(`{
		"method": "card",
		"reference": "trx-%s",
		"currency": "XTS",
		"amount": 1,
		"customer": {
		  "identifier": "email@email.com"
		},
		"card": {
		   "pan": "4242424242424242",
		   "holder_name": "Darth Vader",
		   "cvv": "123",
		   "exp_month": "10",
		   "exp_year": "2035"
		}
	}`, time.Now().Unix()))

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/payment", apiUrl), bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	if err := signRequest(apiKey, apiSecret, request); err != nil {
		panic(err)
	}

	fmt.Printf("Request: %s\n", body)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	respBts, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Response: %s\n", respBts)

	if resp.StatusCode != 200 {
		panic(fmt.Errorf(
			"got http status code %d, request_id: %s",
			resp.StatusCode,
			resp.Header.Get("x-request-id"),
		))
	}

	var paymentResponse map[string]interface{}
	if err := json.Unmarshal(respBts, &paymentResponse); err != nil {
		panic(fmt.Errorf("unable to decode response body - %s", err.Error()))
	}

	if status, ok := paymentResponse["status"]; !ok {
		panic(fmt.Errorf("undefined `status` field"))
	} else {
		status = status.(string)

		if status != "success" {
			panic(fmt.Errorf("invalid payment status - %s", status))
		} else {
			fmt.Println("Yee baby!")
		}
	}
}

func signRequest(key, secret string, req *http.Request) error {
	if len(key) == 0 {
		return fmt.Errorf("empty api key")
	}
	if len(secret) == 0 {
		return fmt.Errorf("empty api secret")
	}

	bodyCopy, err := req.GetBody()
	if err != nil {
		return err
	}

	bts, err := ioutil.ReadAll(bodyCopy)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write(bts)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	signature := fmt.Sprintf("host: %sdigest: %scontent-length: %d", req.Host, digest, req.ContentLength)
	fmt.Printf("Signature Payload - %s\n", signature)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signature))
	signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	var authorization = fmt.Sprintf(
		"Signature keyId=\"%s\", algorithm=\"HmacSHA256\", headers=\"host digest content-length\", signature=\"%s\"",
		key,
		signature,
	)

	req.Header.Set("Host", req.Host)
	req.Header.Set("Digest", digest)
	req.Header.Set("Authorization", authorization)

	return nil
}
