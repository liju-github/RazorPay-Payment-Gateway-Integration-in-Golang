package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/razorpay/razorpay-go"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	router := gin.Default()

	router.Use(corsMiddleware())

	router.POST("/create-order", createRazorpayOrder)
	router.POST("/payment-callback", PaymentGatewayCallback)

	router.Run(":8080")
}


func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

func createRazorpayOrder(c *gin.Context) {

	client := razorpay.NewClient(os.Getenv("RAZORPAY_KEY_ID"), os.Getenv("RAZORPAY_KEY_SECRET"))

	data := map[string]interface{}{
		"amount":          5000, // amount in smallest currency unit
		"currency":        "INR",
		"receipt":         "receipt#1",
		"payment_capture": 1,
	}

	order, err := client.Order.Create(data, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responseData := map[string]interface{}{
		"id":     order["id"],
		"amount": order["amount"],
		"key":    os.Getenv("RAZORPAY_KEY_ID"), // Include the Key ID
	}

	c.JSON(http.StatusOK, responseData)
}

type Payment struct {
	PaymentID string `json:"razorpay_payment_id"`
	OrderID   string `json:"razorpay_order_id"`
	Signature string `json:"razorpay_signature"`
}

func PaymentGatewayCallback(c *gin.Context) {
	var Payment Payment

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to read request body"})
		return
	}
	fmt.Println("Received request body:", string(body))
	defer c.Request.Body.Close()

	// Parse the URL-encoded form data
	parsedQuery, err := url.ParseQuery(string(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse query parameters"})
		return
	}

	// Extract individual values
	paymentID, exists := parsedQuery["razorpay_payment_id"]
	if !exists || len(paymentID[0]) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing payment_id parameter"})
		return
	}

	orderID, exists := parsedQuery["razorpay_order_id"]
	if !exists || len(orderID[0]) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing order_id parameter"})
		return
	}

	signature, exists := parsedQuery["razorpay_signature"]
	if !exists || len(signature[0]) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing signature parameter"})
		return
	}

	// Set the extracted values to the Payment struct
	Payment.PaymentID = paymentID[0]
	Payment.OrderID = orderID[0]
	Payment.Signature = signature[0]

	// Now you can proceed with your verification logic
	if !verifyRazorpaySignature(Payment.OrderID, Payment.PaymentID, Payment.Signature, os.Getenv("RAZORPAY_KEY_SECRET")) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to verify",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"paymentData": Payment,
	})
}

func verifyRazorpaySignature(orderID, paymentID, signature, secret string) bool {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(orderID + "|" + paymentID))
	computedSignature := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(computedSignature), []byte(signature))
}
