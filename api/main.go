package main

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"
    "io"
    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "go.mongodb.org/mongo-driver/mongo/readpref"
    "golang.org/x/crypto/bcrypt"
)

// Constants
const (
    jwtSecretEnv     = "28f907b32a4717f4c543e9515d67527bab09b762d43bac93db742241aae4c50d48cfc78a6bf4155b8403006fec5f864236ad1a4ea94a57798ccd4db031829fa14ff45d53a62fcbe237ba38326b619b27ef67d50ba66889c4647dd0ca8204414353ae696bb671b18cb9df45a72921df2cedee15d9da36501a634a1ce96869c03768bd8144783cbdb6656ea03295949e226c8c7388f73ab31dbe0f8fdde18d30dfe4463d32dc352a310fc504a36eb1add24daa5e50d4e47413f691649631b8a2b7cf1110d36748bc95136dd4e9a34a7a14464e096b389e47d857bb3fbaaf5036684d41992503f6e2f0e7827be55c47f47e23b4d58c25bce2bfc16c6baae39992ca"
    mongoURIEnv      = "mongodb+srv://machinelearner646:S2WJjm80GcgaqMiV@cluster0.aiigs.mongodb.net/goapp?retryWrites=true&w=majority&appName=Cluster0"
    defaultPort      = ":8081"
    bcryptCost       = 12
    tokenExpiryHours = 24
)

// MongoDB Variables
var (
    client     *mongo.Client
    collection *mongo.Collection
    jwtSecret  []byte
)

// User Struct with additional fields 
//Add address details all fileds in tihs 
type User struct {
    ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name        string             `bson:"name" json:"name" binding:"required"`
    Email       string             `bson:"email" json:"email" binding:"required,email"`
    Username    string             `bson:"username" json:"username" binding:"required"`
    Password    string             `bson:"password" json:"password" binding:"required,min=8"`
    ProfilePic  string             `bson:"profile_pic" json:"profile_pic"`
    Phone       string             `bson:"phone" json:"phone" binding:"required"`
    DateOfBirth time.Time          `bson:"date_of_birth" json:"date_of_birth" binding:"required"`
    Gender      string             `bson:"gender" json:"gender" binding:"required"`
    Address     string             `bson:"address" json:"address" binding:"required"`
    City        string             `bson:"city" json:"city" binding:"required"`
    State       string             `bson:"state" json:"state" binding:"required"`
    Country     string             `bson:"country" json:"country" binding:"required"`
    pinCode     string             `bson:"zip_code" json:"zip_code" binding:"required"`
    Role        string             `bson:"role" json:"role" default:"user"`
    CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
    IsActive    bool               `bson:"is_active" json:"is_active" default:"true"`
    Preferences     map[string]string  `bson:"preferences" json:"preferences"` // e.g., {"favorite_genre": "sci-fi"}
    BehaviorScore   float64            `bson:"behavior_score" json:"behavior_score"` // AI-calculated score
    LastPrediction  time.Time          `bson:"last_prediction" json:"last_prediction"`
}


// // AI-powered recommendation endpoint
// func handleUserRecommendations(c *gin.Context) {
//     email, _ := c.Get("email")

//     ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//     defer cancel()

//     var user User
//     if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
//         c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
//         return
//     }

//     // Simulate AI recommendation (replace with real AI logic)
//     recommendations := map[string]interface{}{
//         "suggested_content": "AI-based content for " + user.City,
//         "product":           "Personalized item based on " + user.Gender,
//     }

//     c.JSON(http.StatusOK, SuccessResponse{
//         Message: "Recommendations generated",
//         Data:    recommendations,
//     })
// }

// AI-powered anomaly detection
func handleAnomalyDetection(c *gin.Context) {
    email, _ := c.Get("email")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    // Simulate AI anomaly check (replace with real ML model)
    anomalyScore := calculateAnomalyScore(user) // Custom function
    if anomalyScore > 0.8 {
        c.JSON(http.StatusOK, SuccessResponse{
            Message: "Potential anomaly detected",
            Data:    gin.H{"score": anomalyScore},
        })
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "No anomalies detected",
        Data:    gin.H{"score": anomalyScore},
    })
}

// Placeholder for anomaly score calculation
func calculateAnomalyScore(user User) float64 {
    // Replace with real ML model logic
    return 0.3 // Dummy value
}

// ErrorResponse struct
type ErrorResponse struct {
    Error string `json:"error"`
}

// SuccessResponse struct
type SuccessResponse struct {
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}

// Initialize environment variables
func init() {
    jwtSecret = []byte(getEnvOrDefault(jwtSecretEnv, "your_secret_key"))
}

// Get environment variable or default
func getEnvOrDefault(key, defaultValue string) string {
    if value, exists := os.LookupEnv(key); exists {
        return value
    }
    return defaultValue
}

// Generate JWT token
func generateJWT(user User) (string, error) {
    claims := jwt.MapClaims{
        "email": user.Email,
        "role":  user.Role,
        "exp":   time.Now().Add(time.Hour * tokenExpiryHours).Unix(),
        "iat":   time.Now().Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

// Auth Middleware with role checking
func authMiddleware(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, ErrorResponse{"Authorization token required"})
            c.Abort()
            return
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, ErrorResponse{"Invalid token"})
            c.Abort()
            return
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            c.JSON(http.StatusUnauthorized, ErrorResponse{"Invalid token claims"})
            c.Abort()
            return
        }

        // Role checking
        userRole := claims["role"].(string)
        if len(roles) > 0 {
            hasRole := false
            for _, role := range roles {
                if userRole == role {
                    hasRole = true
                    break
                }
            }
            if !hasRole {
                c.JSON(http.StatusForbidden, ErrorResponse{"Insufficient permissions"})
                c.Abort()
                return
            }
        }

        c.Set("email", claims["email"])
        c.Set("role", userRole)
        c.Next()
    }
}

// // AI-powered recommendation endpoint
// func handleUserRecommendations(c *gin.Context) {
//     email, _ := c.Get("email")

//     ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//     defer cancel()

//     var user User
//     if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
//         c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
//         return
//     }

//     // Simulate AI recommendation (replace with real AI logic)
//     recommendations := map[string]interface{}{
//         "suggested_content": "AI-based content for " + user.City,
//         "product":           "Personalized item based on " + user.Gender,
//     }

//     c.JSON(http.StatusOK, SuccessResponse{
//         Message: "Recommendations generated",
//         Data:    recommendations,
//     })
// }

// AI-powered anomaly detection
func handleAnomalyDetection(c *gin.Context) {
    email, _ := c.Get("email")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    // Simulate AI anomaly check (replace with real ML model)
    anomalyScore := calculateAnomalyScore(user) // Custom function
    if anomalyScore > 0.8 {
        c.JSON(http.StatusOK, SuccessResponse{
            Message: "Potential anomaly detected",
            Data:    gin.H{"score": anomalyScore},
        })
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "No anomalies detected",
        Data:    gin.H{"score": anomalyScore},
    })
}

// Placeholder for anomaly score calculation
func calculateAnomalyScore(user User) float64 {
    // Replace with real ML model logic
    return 0.3 // Dummy value
}// Recommendation struct to standardize response
type Recommendation struct {
    Content string `json:"content"`
    Product string `json:"product"`
}

// generateRecommendations simulates an AI model for now
func generateRecommendations(user User) Recommendation {
    rec := Recommendation{}

    // Rule-based logic (replace with ML model later)
    switch user.City {
    case "New York":
        rec.Content = "Latest Broadway shows"
        rec.Product = "City tour package"
    case "San Francisco":
        rec.Content = "Tech documentaries"
        rec.Product = "Gadgets"
    default:
        rec.Content = "General news"
        rec.Product = "Gift card"
    }

    // Adjust based on gender
    if user.Gender == "male" {
        rec.Product = "Tech gadgets"
    } else if user.Gender == "female" {
        rec.Product = "Fashion accessories"
    }

    // Incorporate preferences if available
    if category, ok := user.Preferences["favorite_category"]; ok {
        rec.Product = category + " item"
    }

    return rec
}

// handleUserRecommendations provides AI-driven suggestions
func handleUserRecommendations(c *gin.Context) {
    email, exists := c.Get("email")
    if !exists {
        c.JSON(http.StatusUnauthorized, ErrorResponse{"User not authenticated"})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    // Generate AI recommendations
    recommendations := generateRecommendations(user)

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Recommendations generated successfully",
        Data:    recommendations,
    })
}    protected.GET("/recommendations", handleUserRecommendations)
    protected.GET("/anomaly", handleAnomalyDetection)

// Setup Database
func setupDatabase() (*mongo.Client, error) {
    mongoURI := getEnvOrDefault(mongoURIEnv, "mongodb+srv://machinelearner646:S2WJjm80GcgaqMiV@cluster0.aiigs.mongodb.net/goapp?retryWrites=true&w=majority")
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    clientOptions := options.Client().ApplyURI(mongoURI)
    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
    }

    if err = client.Ping(ctx, readpref.Primary()); err != nil {
        return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
    }

    return client, nil
}

// Handle Register
func handleRegister(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Check existing email or username
    count, err := collection.CountDocuments(ctx, bson.M{
        "$or": []bson.M{
            {"email": user.Email},
            {"username": user.Username},
        },
    })
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Database error"})
        return
    }
    if count > 0 {
        c.JSON(http.StatusConflict, ErrorResponse{"Email or username already exists"})
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcryptCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Password hashing failed"})
        return
    }

    // Set additional fields
    user.Password = string(hashedPassword)
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()
    user.Role = "user"
    user.IsActive = true

    result, err := collection.InsertOne(ctx, user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to register user"})
        return
    }

    user.ID = result.InsertedID.(primitive.ObjectID)
    token, err := generateJWT(user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to generate token"})
        return
    }

    c.JSON(http.StatusCreated, SuccessResponse{
        Message: "Registration successful",
        Data:    gin.H{"token": token},
    })
}

// Handle Login
func handleLogin(c *gin.Context) {
    var loginData struct {
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&loginData); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": loginData.Email}).Decode(&user); err != nil {
        c.JSON(http.StatusUnauthorized, ErrorResponse{"Invalid credentials"})
        return
    }

    // if !user.IsActive {
    //     c.JSON(http.StatusForbidden, ErrorResponse{"Account is deactivated"})
    //     return
    // }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, ErrorResponse{"Invalid credentials"})
        return
    }

    token, err := generateJWT(user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Login successful",
        Data:    gin.H{"token": token},
    })
}

// Handle Forgot Password
func handleForgotPassword(c *gin.Context) {
    var request struct {
        Email string `json:"email" binding:"required,email"`
    }
    
    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": request.Email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    resetToken := make([]byte, 32)
    if _, err := rand.Read(resetToken); err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to generate reset token"})
        return
    }
    
    resetTokenStr := hex.EncodeToString(resetToken)
    expiresAt := time.Now().Add(1 * time.Hour)

    _, err := collection.UpdateOne(ctx,
        bson.M{"email": request.Email},
        bson.M{
            "$set": bson.M{
                "reset_token":     resetTokenStr,
                "reset_token_exp": expiresAt,
                "updated_at":      time.Now(),
            },
        },
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to save reset token"})
        return
    }

    // In production, send this token via email
    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Reset token generated successfully",
        Data:    gin.H{"reset_token": resetTokenStr, "expires_at": expiresAt},
    })
}

// Handle Reset Password
func handleResetPassword(c *gin.Context) {
    var request struct {
        Email      string `json:"email" binding:"required,email"`
        ResetToken string `json:"reset_token" binding:"required"`
        NewPassword string `json:"new_password" binding:"required,min=8"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    err := collection.FindOne(ctx, bson.M{
        "email":       request.Email,
        "reset_token": request.ResetToken,
        "reset_token_exp": bson.M{"$gt": time.Now()},
    }).Decode(&user)

    if err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{"Invalid or expired reset token"})
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcryptCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to hash password"})
        return
    }

    _, err = collection.UpdateOne(ctx,
        bson.M{"email": request.Email},
        bson.M{
            "$set": bson.M{
                "password":        string(hashedPassword),
                "reset_token":     nil,
                "reset_token_exp": nil,
                "updated_at":      time.Now(),
            },
        },
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to update password"})
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{Message: "Password reset successful"})
}

// Handle User Profile
func handleUserProfile(c *gin.Context) {
    email, _ := c.Get("email")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    user.Password = "" // Remove password from response
    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Profile retrieved successfully",
        Data:    user,
    })
}

// Handle Update Profile
func handleUpdateProfile(c *gin.Context) {
    email, _ := c.Get("email")
    
    var updateData struct {
        Name        string    `json:"name"`
        Username    string    `json:"username"`
        ProfilePic  string    `json:"profile_pic"`
        Phone       string    `json:"phone"`
        DateOfBirth time.Time `json:"date_of_birth"`
        Gender      string    `json:"gender"`
    }

    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{err.Error()})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    updateFields := bson.M{
        "updated_at": time.Now(),
    }
    if updateData.Name != "" {
        updateFields["name"] = updateData.Name
    }
    if updateData.Username != "" {
        updateFields["username"] = updateData.Username
    }
    if updateData.ProfilePic != "" {
        updateFields["profile_pic"] = updateData.ProfilePic
    }
    if updateData.Phone != "" {
        updateFields["phone"] = updateData.Phone
    }
    if !updateData.DateOfBirth.IsZero() {
        updateFields["date_of_birth"] = updateData.DateOfBirth
    }
    if updateData.Gender != "" {
        updateFields["gender"] = updateData.Gender
    }

    result, err := collection.UpdateOne(ctx,
        bson.M{"email": email},
        bson.M{"$set": updateFields},
    )
    if err != nil || result.ModifiedCount == 0 {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Failed to update profile"})
        return
    }

    c.JSON(http.StatusOK, SuccessResponse{Message: "Profile updated successfully"})
}

// Get All Users (Admin only)
func getAllUsers(c *gin.Context) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    cursor, err := collection.Find(ctx, bson.M{"is_active": true})
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Database error"})
        return
    }
    defer cursor.Close(ctx)

    var users []User
    if err = cursor.All(ctx, &users); err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{"Data retrieval error"})
        return
    }

    for i := range users {
        users[i].Password = ""
    }

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Users retrieved successfully",
        Data:    users,
    })
}

func handleFileUpload(c *gin.Context) {
    profilePic, header, err := c.Request.FormFile("profile_pic")
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Error retrieving file: " + err.Error()})
        return
    }
    defer profilePic.Close() // Ensure the file is closed after processing

    // Create a temporary file to store the uploaded profile picture
    filename := header.Filename
    filepath := fmt.Sprintf("uploads/%s", filename)
    out, err := os.Create(filepath)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving file: " + err.Error()})
        return
    }
    defer out.Close()

    // Copy the file content to the new file
    _, err = io.Copy(out, profilePic)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error copying file: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "filepath": filepath})
}

// Recommendation struct to standardize response
type Recommendation struct {
    Content string `json:"content"`
    Product string `json:"product"`
}

// generateRecommendations simulates an AI model for now
func generateRecommendations(user User) Recommendation {
    rec := Recommendation{}

    // Rule-based logic (replace with ML model later)
    switch user.City {
    case "New York":
        rec.Content = "Latest Broadway shows"
        rec.Product = "City tour package"
    case "San Francisco":
        rec.Content = "Tech documentaries"
        rec.Product = "Gadgets"
    default:
        rec.Content = "General news"
        rec.Product = "Gift card"
    }

    // Adjust based on gender
    if user.Gender == "male" {
        rec.Product = "Tech gadgets"
    } else if user.Gender == "female" {
        rec.Product = "Fashion accessories"
    }

    // Incorporate preferences if available
    if category, ok := user.Preferences["favorite_category"]; ok {
        rec.Product = category + " item"
    }

    return rec
}

// handleUserRecommendations provides AI-driven suggestions
func handleUserRecommendations(c *gin.Context) {
    email, exists := c.Get("email")
    if !exists {
        c.JSON(http.StatusUnauthorized, ErrorResponse{"User not authenticated"})
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user User
    if err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
        c.JSON(http.StatusNotFound, ErrorResponse{"User not found"})
        return
    }

    // Generate AI recommendations
    recommendations := generateRecommendations(user)

    c.JSON(http.StatusOK, SuccessResponse{
        Message: "Recommendations generated successfully",
        Data:    recommendations,
    })
}
func main() {
    var err error
    client, err = setupDatabase()
    if err != nil {
        log.Fatalf("Database connection failed: %v", err)
    }
    defer client.Disconnect(context.Background())

    collection = client.Database("goapp").Collection("users")

    r := gin.Default()
    
    // CORS configuration
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"http://localhost:4200", "https://your-production-domain.com"},
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }))

    // Public routes
    r.POST("/api/signup", handleRegister)
    r.POST("/api/login", handleLogin)
    r.POST("/api/forgot-password", handleForgotPassword)
    r.POST("/api/reset-password", handleResetPassword)
    r.Static("/uploads", "./uploads")
    r.POST("/api/upload", handleFileUpload)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(authMiddleware())
    protected.GET("/profile", handleUserProfile)
    protected.PUT("/profile", handleUpdateProfile)
    protected.GET("/recommendations", handleUserRecommendations)
    protected.GET("/anomaly", handleAnomalyDetection)


    // Admin routes
    admin := r.Group("/api/admin")
    admin.Use(authMiddleware("admin"))
    admin.GET("/users", getAllUsers)

    port := getEnvOrDefault("PORT", defaultPort)
    if err := r.Run(port); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
    fmt.Printf("Server running on port %s\n", port)
}