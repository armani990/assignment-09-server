
import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
const client = new MongoClient(
  `mongodb://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASSWORD)}@ac-u1in1l5-shard-00-00.b1dyndt.mongodb.net:27017,ac-u1in1l5-shard-00-01.b1dyndt.mongodb.net:27017,ac-u1in1l5-shard-00-02.b1dyndt.mongodb.net:27017/?ssl=true&replicaSet=atlas-66paj9-shard-0&authSource=admin`
);

// Connect to MongoDB
export async function connectToMongoDB() {
  try {
    await client.connect();

    console.log("You successfully connected to MongoDB!");

    return client;
  } catch (error) {
    console.error("MongoDB Connection Failed:", error);
    throw error;
  }
}

// Database Connection
const connectedClient = await connectToMongoDB();

const database = connectedClient.db("pizzahub");

// Test Route
app.get("/", (req, res) => {
  res.send("PizzaHub Server is Running!");
});

// Start Server
app.listen(port, () => {
  console.log(`PizzaHub server is running on port ${port}`);
});
