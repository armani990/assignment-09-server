
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
const ordersCollection = database.collection("orders");

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


// Admin: Get All Menu Items
app.get(
  "/admin/menu-items",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { status } = req.query;

      const filter = {};

      if (status) {
        const allowedStatuses = [
          "pending",
          "approved",
          "rejected",
          "inactive",
        ];

        if (!allowedStatuses.includes(status)) {
          return res.status(400).json({
            message: "Invalid menu item status",
          });
        }

        filter.status = status;
      }

      const menuItems = await menuItemsCollection
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).json(menuItems);
    } catch (error) {
      console.error("Get Menu Items Error:", error);

      res.status(500).json({
        message: "Failed to fetch menu items",
      });
    }
  }
);

// Admin: Update Menu Item Status
app.patch(
  "/admin/menu-items/:id/status",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid menu item ID",
        });
      }

      const allowedStatuses = ["approved", "rejected"];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          message: "Status must be approved or rejected",
        });
      }

      const result = await menuItemsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          message: "Menu item not found",
        });
      }

      res.status(200).json({
        message: `Menu item ${status} successfully`,
      });
    } catch (error) {
      console.error("Update Menu Item Status Error:", error);

      res.status(500).json({
        message: "Failed to update menu item status",
      });
    }
  }
);

/* ================================
   VENDOR: GET OWN MENU ITEMS
================================ */

app.get(
  "/vendor/menu-items",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const menuItems = await menuItemsCollection
        .find({
          vendorId: req.authUser._id,
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).json(menuItems);
    } catch (error) {
      console.error("Get Vendor Menu Items Error:", error);

      res.status(500).json({
        message: "Failed to fetch your menu items",
      });
    }
  }
);

/* ================================
   VENDOR: UPDATE OWN MENU ITEM
================================ */

app.put(
  "/vendor/menu-items/:id",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        itemName,
        category,
        description,
        price,
        location,
        images,
      } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid menu item ID",
        });
      }

      if (
        !itemName?.trim() ||
        !category?.trim() ||
        !description?.trim() ||
        !location?.trim() ||
        !Array.isArray(images) ||
        images.length === 0
      ) {
        return res.status(400).json({
          message: "All fields and at least one image are required",
        });
      }

      const itemPrice = Number(price);

      if (!Number.isFinite(itemPrice) || itemPrice <= 0) {
        return res.status(400).json({
          message: "Price must be a positive number",
        });
      }

      const validImages = images.every((image) => {
        if (typeof image !== "string") return false;

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

      const result = await menuItemsCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.authUser._id,
        },
        {
          $set: {
            itemName: itemName.trim(),
            category: category.trim(),
            description: description.trim(),
            price: itemPrice,
            location: location.trim(),
            images,
            status: "pending",
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          message: "Menu item not found or you do not own this item",
        });
      }

      res.status(200).json({
        message: "Menu item updated and sent for admin approval",
      });
    } catch (error) {
      console.error("Update Vendor Menu Item Error:", error);

      res.status(500).json({
        message: "Failed to update menu item",
      });
    }
  }
);

/* ================================
   VENDOR: DELETE OWN MENU ITEM
================================ */

app.delete(
  "/vendor/menu-items/:id",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid menu item ID",
        });
      }

      const result = await menuItemsCollection.deleteOne({
        _id: new ObjectId(id),
        vendorId: req.authUser._id,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({
          message: "Menu item not found or you do not own this item",
        });
      }

      res.status(200).json({
        message: "Menu item deleted successfully",
      });
    } catch (error) {
      console.error("Delete Vendor Menu Item Error:", error);

      res.status(500).json({
        message: "Failed to delete menu item",
      });
    }
  }
);


/* ================================
   PUBLIC: GET FEATURED MENU ITEMS
================================ */

app.get("/menu-items/featured", async (req, res) => {
  try {
    const menuItems = await menuItemsCollection
      .find({
        status: "approved",
      })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray();

    res.status(200).json(menuItems);
  } catch (error) {
    console.error("Get Featured Menu Items Error:", error);

    res.status(500).json({
      message: "Failed to fetch featured menu items",
    });
  }
});


/* PUBLIC: GET SINGLE APPROVED MENU ITEM */
app.get("/menu-items/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        message: "Invalid menu item ID",
      });
    }

    const menuItem = await menuItemsCollection.findOne({
      _id: new ObjectId(id),
      status: "approved",
    });

    if (!menuItem) {
      return res.status(404).json({
        message: "Menu item not found",
      });
    }

    const vendor = await usersCollection.findOne({
      _id: menuItem.vendorId,
    });

    res.status(200).json({
      ...menuItem,
      vendor: {
        name: vendor?.businessName || vendor?.name || "PizzaHub Vendor",
        email: vendor?.email || "",
      },
    });
  } catch (error) {
    console.error("Get Menu Item Details Error:", error);

    res.status(500).json({
      message: "Failed to fetch menu item details",
    });
  }
});



/* CUSTOMER: PLACE ORDER */
app.post(
  "/orders",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      const {
        itemId,
        deliveryDate,
        deliveryAddress,
        message,
      } = req.body;

      if (
        !ObjectId.isValid(itemId) ||
        !deliveryDate ||
        !deliveryAddress?.trim()
      ) {
        return res.status(400).json({
          message: "Item, delivery date and address are required",
        });
      }

      // Validate date format
      if (!/^\d{4}-\d{2}-\d{2}$/.test(deliveryDate)) {
        return res.status(400).json({
          message: "Invalid delivery date",
        });
      }

      const parsedDate = new Date(`${deliveryDate}T00:00:00.000Z`);

      if (
        Number.isNaN(parsedDate.getTime()) ||
        parsedDate.toISOString().slice(0, 10) !== deliveryDate
      ) {
        return res.status(400).json({
          message: "Invalid delivery date",
        });
      }

      if (deliveryAddress.trim().length > 500) {
        return res.status(400).json({
          message: "Delivery address is too long",
        });
      }

      if (
        message !== undefined &&
        (typeof message !== "string" || message.length > 500)
      ) {
        return res.status(400).json({
          message: "Message must be 500 characters or fewer",
        });
      }

      // Get item from database
      const menuItem = await menuItemsCollection.findOne({
        _id: new ObjectId(itemId),
        status: "approved",
      });

      if (!menuItem) {
        return res.status(404).json({
          message: "This pizza is not available for ordering",
        });
      }

      // Prevent ordering own item
      if (
        String(menuItem.vendorId) === String(req.authUser._id)
      ) {
        return res.status(403).json({
          message: "You cannot order your own item",
        });
      }

      // Prevent duplicate active orders for same date
      const existingOrder = await ordersCollection.findOne({
        itemId: menuItem._id,
        customerId: req.authUser._id,
        deliveryDate,
        status: { $in: ["pending", "accepted"] },
      });

      if (existingOrder) {
        return res.status(409).json({
          message: "You already have an active order for this pizza on this date",
        });
      }

      // Vendor ID comes from database, never from client
      const newOrder = {
        itemId: menuItem._id,
        vendorId: menuItem.vendorId,
        customerId: req.authUser._id,
        deliveryDate,
        deliveryAddress: deliveryAddress.trim(),
        message: message?.trim() || "",
        status: "pending",
        createdAt: new Date(),
      };

      const result = await ordersCollection.insertOne(newOrder);

      res.status(201).json({
        message: "Order placed successfully",
        orderId: result.insertedId,
      });
    } catch (error) {
      console.error("Place Order Error:", error);

      res.status(500).json({
        message: "Failed to place order",
      });
    }
  }
);

/* CUSTOMER: GET OWN ORDERS */
app.get(
  "/customer/orders",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      const orders = await ordersCollection
        .aggregate([
          {
            $match: {
              customerId: req.authUser._id,
            },
          },
          {
            $sort: {
              createdAt: -1,
            },
          },
          {
            $lookup: {
              from: "menuItems",
              localField: "itemId",
              foreignField: "_id",
              as: "item",
            },
          },
          {
            $unwind: {
              path: "$item",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $lookup: {
              from: "user",
              localField: "vendorId",
              foreignField: "_id",
              as: "vendor",
            },
          },
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              itemId: 1,
              vendorId: 1,
              customerId: 1,
              deliveryDate: 1,
              deliveryAddress: 1,
              message: 1,
              status: 1,
              createdAt: 1,

              item: {
                itemName: "$item.itemName",
                images: "$item.images",
                price: "$item.price",
                category: "$item.category",
              },

              vendor: {
                name: "$vendor.name",
                businessName: "$vendor.businessName",
                email: "$vendor.email",
              },
            },
          },
        ])
        .toArray();

      res.status(200).json(orders);
    } catch (error) {
      console.error("Get Customer Orders Error:", error);

      res.status(500).json({
        message: "Failed to fetch customer orders",
      });
    }
  }
);

/* CUSTOMER: CANCEL OWN PENDING ORDER */
app.patch(
  "/customer/orders/:id/cancel",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid order ID",
        });
      }

      const result = await ordersCollection.updateOne(
        {
          _id: new ObjectId(id),
          customerId: req.authUser._id,
          status: "pending",
        },
        {
          $set: {
            status: "cancelled",
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        const existingOrder = await ordersCollection.findOne({
          _id: new ObjectId(id),
          customerId: req.authUser._id,
        });

        if (!existingOrder) {
          return res.status(404).json({
            message: "Order not found",
          });
        }

        return res.status(409).json({
          message: "Only pending orders can be cancelled",
        });
      }

      res.status(200).json({
        message: "Order cancelled successfully",
      });
    } catch (error) {
      console.error("Cancel Customer Order Error:", error);

      res.status(500).json({
        message: "Failed to cancel order",
      });
    }
  }
);

/* VENDOR: GET OWN CUSTOMER ORDERS */
app.get(
  "/vendor/orders",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const orders = await ordersCollection
        .aggregate([
          {
            $match: {
              vendorId: req.authUser._id,
            },
          },
          {
            $sort: {
              createdAt: -1,
            },
          },
          {
            $lookup: {
              from: "menuItems",
              localField: "itemId",
              foreignField: "_id",
              as: "item",
            },
          },
          {
            $unwind: {
              path: "$item",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $lookup: {
              from: "user",
              localField: "customerId",
              foreignField: "_id",
              as: "customer",
            },
          },
          {
            $unwind: {
              path: "$customer",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              itemId: 1,
              vendorId: 1,
              customerId: 1,
              deliveryDate: 1,
              deliveryAddress: 1,
              message: 1,
              status: 1,
              createdAt: 1,
              updatedAt: 1,

              item: {
                itemName: "$item.itemName",
                images: "$item.images",
                price: "$item.price",
                category: "$item.category",
                location: "$item.location",
              },

              customer: {
                name: "$customer.name",
                email: "$customer.email",
              },
            },
          },
        ])
        .toArray();

      res.status(200).json(orders);
    } catch (error) {
      console.error("Get Vendor Orders Error:", error);

      res.status(500).json({
        message: "Failed to fetch vendor orders",
      });
    }
  }
);

/* VENDOR: UPDATE OWN ORDER STATUS */
app.patch(
  "/vendor/orders/:id/status",
  verifyToken,
  requireRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid order ID",
        });
      }

      const allowedStatuses = ["accepted", "rejected"];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          message: "Status must be accepted or rejected",
        });
      }

      const result = await ordersCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.authUser._id,
          status: "pending",
        },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        const existingOrder = await ordersCollection.findOne({
          _id: new ObjectId(id),
          vendorId: req.authUser._id,
        });

        if (!existingOrder) {
          return res.status(404).json({
            message: "Order not found",
          });
        }

        return res.status(409).json({
          message: "Only pending orders can be updated",
        });
      }

      res.status(200).json({
        message: `Order ${status} successfully`,
      });
    } catch (error) {
      console.error("Update Vendor Order Status Error:", error);

      res.status(500).json({
        message: "Failed to update order status",
      });
    }
  }
);

/* PUBLIC: GET ALL APPROVED MENU ITEMS */
app.get("/menu-items", async (req, res) => {
  try {
    const { search, category, location, sort } = req.query;

    const filter = {
      status: "approved",
    };

    // Search by item name
    if (search?.trim()) {
      const escapedSearch = search.trim().replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      filter.itemName = {
        $regex: escapedSearch,
        $options: "i",
      };
    }

    // Filter by category
    if (category?.trim()) {
      filter.category = {
        $regex: `^${category.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
        $options: "i",
      };
    }

    // Filter by location
    if (location?.trim()) {
      const escapedLocation = location.trim().replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      filter.location = {
        $regex: escapedLocation,
        $options: "i",
      };
    }

    // Sorting
    const sortOptions = {
      price_asc: { price: 1 },
      price_desc: { price: -1 },
    };

    if (sort && !sortOptions[sort]) {
      return res.status(400).json({
        message: "Invalid sort option",
      });
    }

    const sortQuery = sortOptions[sort] || { createdAt: -1 };

    const menuItems = await menuItemsCollection
      .find(filter)
      .sort(sortQuery)
      .toArray();

    res.status(200).json(menuItems);
  } catch (error) {
    console.error("Get Public Menu Items Error:", error);

    res.status(500).json({
      message: "Failed to fetch menu items",
    });
  }
});


// Start Server
app.listen(port, () => {
  console.log(`PizzaHub server is running on port ${port}`);
});
