
import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// JWT Configuration
const BETTER_AUTH_URL = process.env.BETTER_AUTH_URL;

const JWKS = createRemoteJWKSet(
  new URL("/api/auth/jwks", BETTER_AUTH_URL)
);

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

// Collections
const usersCollection = database.collection("user");
const menuItemsCollection = database.collection("menuItems");

// JWT Verification Middleware
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Unauthorized: Token is required",
      });
    }

    const token = authHeader.split(" ")[1];

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: BETTER_AUTH_URL,
      audience: BETTER_AUTH_URL,
    });

    if (!payload.sub) {
      return res.status(401).json({
        message: "Unauthorized: Invalid token",
      });
    }

    // Find the authenticated user
    const userFilter = ObjectId.isValid(payload.sub)
      ? {
          $or: [
            { _id: new ObjectId(payload.sub) },
            { id: payload.sub },
          ],
        }
      : {
          $or: [
            { _id: payload.sub },
            { id: payload.sub },
          ],
        };

    const user = await usersCollection.findOne(userFilter);

    if (!user) {
      return res.status(401).json({
        message: "Unauthorized: User not found",
      });
    }

    req.user = {
      ...payload,
      role: user.role,
    };

    req.authUser = user;

    next();
  } catch (error) {
    console.error("JWT Verification Failed:", error.message);

    return res.status(401).json({
      message: "Unauthorized: Invalid or expired token",
    });
  }
}

// Role Authorization Middleware
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Forbidden: You do not have permission",
      });
    }

    next();
  };
}

// Test Route
app.get("/", (req, res) => {
  res.send("PizzaHub Server is Running!");
});

// Add Menu Item
app.post(
  "/menu-items",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const {
        itemName,
        category,
        description,
        price,
        location,
        images,
      } = req.body;

      // Validate required fields
      if (
        !itemName?.trim() ||
        !category?.trim() ||
        !description?.trim() ||
        !location?.trim() ||
        price === undefined ||
        !Array.isArray(images) ||
        images.length === 0
      ) {
        return res.status(400).json({
          message: "All fields are required",
        });
      }

      // Validate price
      const itemPrice = Number(price);

      if (!Number.isFinite(itemPrice) || itemPrice <= 0) {
        return res.status(400).json({
          message: "Price must be a valid positive number",
        });
      }

      // Validate ImgBB image URLs
      const validImages = images.every((image) => {
        try {
          const url = new URL(image);

          return (
            url.protocol === "https:" &&
            (url.hostname === "ibb.co" ||
              url.hostname.endsWith(".ibb.co"))
          );
        } catch {
          return false;
        }
      });

      if (!validImages) {
        return res.status(400).json({
          message: "Please provide valid ImgBB image URLs",
        });
      }

      // Prepare menu item
      const newMenuItem = {
        vendorId: req.authUser._id,
        itemName: itemName.trim(),
        category: category.trim(),
        description: description.trim(),
        price: itemPrice,
        location: location.trim(),
        images,
        status: "pending",
        createdAt: new Date(),
      };

      // Save to MongoDB
      const result = await menuItemsCollection.insertOne(newMenuItem);

      res.status(201).json({
        message: "Menu item submitted successfully. Waiting for admin approval.",
        insertedId: result.insertedId,
      });
    } catch (error) {
      console.error("Add Menu Item Error:", error);

      res.status(500).json({
        message: "Failed to add menu item",
      });
    }
  }
);

// Start Server
app.listen(port, () => {
  console.log(`PizzaHub server is running on port ${port}`);
});
