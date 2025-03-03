package models

import (
    "context"
    "fmt"
    "time"
    "log"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "go.mongodb.org/mongo-driver/mongo/readpref"
    
)

type User struct {
    ID          primitive.ObjectID `bson:"_id,omitempty"`
    Name        string             `json:"name" binding:"required"`
    Email       string             `json:"email" binding:"required,email"`
    Username    string             `json:"username" binding:"required"`
    Password    string             `json:"password" binding:"required,min=8"`
    ProfilePic  string             `json:"profile_pic"`
    Phone       string             `json:"phone" binding:"required"`
    DateOfBirth time.Time          `json:"date_of_birth" binding:"required"`
    Gender      string             `json:"gender" binding:"required"`
}

var Client *mongo.Client
var UserCollection *mongo.Collection

func SetupDatabase() {
    var err error

    // MongoDB URI with correct formatting
    mongoURI := "mongodb+srv://machinelearner646:S2WJjm80GcgaqMiV@cluster0.aiigs.mongodb.net/goapp?retryWrites=true&w=majority&appName=Cluster0"

    // Log the URI for debugging
    fmt.Println("Connecting to MongoDB with URI: ", mongoURI)

    clientOptions := options.Client().ApplyURI(mongoURI)

    // Connect to MongoDB Atlas
    Client, err = mongo.Connect(context.Background(), clientOptions)
    if err != nil {
        log.Fatal("Failed to connect to MongoDB:", err)
    }

    // Ping MongoDB to verify the connection
    err = Client.Ping(context.Background(), readpref.Primary())
    if err != nil {
        log.Fatal("Failed to ping MongoDB:", err)
    }

    // Set the User collection
    UserCollection = Client.Database("goapp").Collection("users")
}
