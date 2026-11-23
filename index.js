
import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

const app = express();
const port = process.env.PORT || 5000;

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Middleware
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

const transactionsCollection = database.collection("transactions");
const webhookEventsCollection = database.collection("webhookEvents");

await webhookEventsCollection.createIndex(
    { eventId: 1 },
    { unique: true }
);



/* STRIPE: VERIFY WEBHOOK AND ACTIVATE PREMIUM */

app.post(
    "/webhook/stripe",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        const signature = req.headers["stripe-signature"];

        let event;

        // Verify Stripe webhook signature
        try {
            event = stripe.webhooks.constructEvent(
                req.body,
                signature,
                process.env.STRIPE_WEBHOOK_SECRET
            );
        } catch (error) {
            console.error("Stripe Webhook Signature Error:", error.message);

            return res.status(400).send(`Webhook Error: ${error.message}`);
        }

        try {
            // Prevent duplicate event processing
            const existingEvent = await webhookEventsCollection.findOne({
                eventId: event.id,
            });

            if (existingEvent) {
                return res.status(200).json({
                    received: true,
                    duplicate: true,
                });
            }

            // Activate Premium after successful Checkout
            if (event.type === "checkout.session.completed") {
                const session = event.data.object;

                if (
                    session.mode === "subscription" &&
                    ["paid", "no_payment_required"].includes(
                        session.payment_status
                    )
                ) {
                    const vendorId = session.metadata?.vendorId;

                    const subscriptionId =
                        typeof session.subscription === "string"
                            ? session.subscription
                            : session.subscription?.id;

                    // Verify Checkout Session ownership
                    if (
                        !ObjectId.isValid(vendorId) ||
                        session.client_reference_id !== vendorId ||
                        session.metadata?.plan !== "premium" ||
                        !subscriptionId
                    ) {
                        return res.status(400).json({
                            message: "Invalid subscription information",
                        });
                    }

                    // Find the original pending transaction
                    const transaction = await transactionsCollection.findOne({
                        stripeSessionId: session.id,
                        vendorId: new ObjectId(vendorId),
                        status: { $in: ["pending", "succeeded"] },
                    });

                    if (!transaction) {
                        throw new Error(
                            "Pending subscription transaction not found"
                        );
                    }

                    // Retrieve and verify Stripe Subscription
                    const subscription =
                        await stripe.subscriptions.retrieve(subscriptionId);

                    if (
                        subscription.metadata?.vendorId !== vendorId ||
                        subscription.metadata?.plan !== "premium" ||
                        !["active", "trialing"].includes(subscription.status)
                    ) {
                        throw new Error(
                            "Stripe subscription verification failed"
                        );
                    }

                    // Verify the Premium monthly price
                    const premiumSubscriptionItem =
                        subscription.items.data.find(
                            (item) =>
                                item.price?.unit_amount === 999 &&
                                item.price?.currency === "usd" &&
                                item.price?.recurring?.interval === "month"
                        );

                    if (!premiumSubscriptionItem) {
                        return res.status(400).json({
                            message: "Invalid Premium subscription price",
                        });
                    }

                    // Get subscription expiry timestamp
                    const periodEnd =
                        premiumSubscriptionItem.current_period_end ??
                        subscription.current_period_end;

                    if (
                        typeof periodEnd !== "number" ||
                        !Number.isFinite(periodEnd)
                    ) {
                        throw new Error(
                            "Invalid subscription expiry date"
                        );
                    }

                    const expiresAt = new Date(periodEnd * 1000);

                    const stripeCustomerId =
                        typeof session.customer === "string"
                            ? session.customer
                            : session.customer?.id;

                    // Activate Premium for the vendor
                    const userResult = await usersCollection.updateOne(
                        {
                            _id: new ObjectId(vendorId),
                            role: "vendor",
                        },
                        {
                            $set: {
                                subscriptionPlan: "premium",
                                subscriptionExpiresAt: expiresAt,
                                stripeSubscriptionId: subscription.id,
                                stripeCustomerId,
                                updatedAt: new Date(),
                            },
                        }
                    );

                    if (userResult.matchedCount === 0) {
                        throw new Error("Vendor account not found");
                    }

                    // Mark transaction as successful
                    const transactionResult =
                        await transactionsCollection.updateOne(
                            {
                                _id: transaction._id,
                                vendorId: new ObjectId(vendorId),
                            },
                            {
                                $set: {
                                    status: "succeeded",
                                    stripeSubscriptionId: subscription.id,
                                    paidAt: transaction.paidAt || new Date(),
                                },
                            }
                        );

                    if (transactionResult.matchedCount === 0) {
                        throw new Error(
                            "Failed to update subscription transaction"
                        );
                    }
                }
            }

            // Handle subscription updates and cancellations
            if (
                event.type === "customer.subscription.updated" ||
                event.type === "customer.subscription.deleted"
            ) {
                const subscription = event.data.object;
                const vendorId = subscription.metadata?.vendorId;

                if (
                    !ObjectId.isValid(vendorId) ||
                    subscription.metadata?.plan !== "premium"
                ) {
                    return res.status(400).json({
                        message: "Invalid subscription metadata",
                    });
                }

                const isActive =
                    event.type !== "customer.subscription.deleted" &&
                    ["active", "trialing"].includes(subscription.status);

                let expiresAt = null;

                if (isActive) {
                    const subscriptionItem = subscription.items.data[0];

                    const periodEnd =
                        subscriptionItem?.current_period_end ??
                        subscription.current_period_end;

                    if (
                        typeof periodEnd !== "number" ||
                        !Number.isFinite(periodEnd)
                    ) {
                        throw new Error(
                            "Invalid subscription expiry date"
                        );
                    }

                    expiresAt = new Date(periodEnd * 1000);
                }

                const userResult = await usersCollection.updateOne(
                    {
                        _id: new ObjectId(vendorId),
                        role: "vendor",
                    },
                    {
                        $set: {
                            subscriptionPlan: isActive ? "premium" : "free",
                            subscriptionExpiresAt: expiresAt,
                            stripeSubscriptionId: subscription.id,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (userResult.matchedCount === 0) {
                    throw new Error("Vendor account not found");
                }
            }

            // Save processed event ID only after successful processing
            await webhookEventsCollection.insertOne({
                eventId: event.id,
                eventType: event.type,
                processedAt: new Date(),
            });

            return res.status(200).json({
                received: true,
            });
        } catch (error) {
            if (error.code === 11000) {
                return res.status(200).json({
                    received: true,
                    duplicate: true,
                });
            }

            console.error("Stripe Webhook Processing Error:", error);

            return res.status(500).json({
                message: "Webhook processing failed",
            });
        }
    }
);


// JSON Middleware (must stay after the Stripe webhook route)
app.use(express.json());

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

            // Check vendor subscription and active menu item limit
            const isPremiumActive =
                req.authUser.subscriptionPlan === "premium" &&
                req.authUser.subscriptionExpiresAt &&
                new Date(req.authUser.subscriptionExpiresAt) > new Date();

            if (!isPremiumActive) {
                const activeMenuCount =
                    await menuItemsCollection.countDocuments({
                        vendorId: req.authUser._id,
                        status: "approved",
                    });

                if (activeMenuCount >= 3) {
                    return res.status(403).json({
                        message:
                            "You have reached the Free plan limit of 3 active menu items. Upgrade to Premium to add more menu items.",
                    });
                }
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


/* ADMIN: UPDATE MENU ITEM STATUS */

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

            // Find the menu item
            const menuItem = await menuItemsCollection.findOne({
                _id: new ObjectId(id),
            });

            if (!menuItem) {
                return res.status(404).json({
                    message: "Menu item not found",
                });
            }

            // Check vendor account
            const vendor = await usersCollection.findOne({
                _id: menuItem.vendorId,
                role: "vendor",
            });

            if (!vendor) {
                return res.status(404).json({
                    message: "Vendor account not found",
                });
            }

            // Enforce Free plan limit before approval
            if (
                status === "approved" &&
                menuItem.status !== "approved"
            ) {
                const isPremiumActive =
                    vendor.subscriptionPlan === "premium" &&
                    vendor.subscriptionExpiresAt &&
                    new Date(vendor.subscriptionExpiresAt) > new Date();

                if (!isPremiumActive) {
                    const activeMenuCount =
                        await menuItemsCollection.countDocuments({
                            vendorId: vendor._id,
                            status: "approved",
                        });

                    if (activeMenuCount >= 3) {
                        return res.status(403).json({
                            message:
                                "This vendor has reached the Free plan limit of 3 active menu items. Upgrade to Premium to approve more items.",
                        });
                    }
                }
            }

            // Update menu item status
            const result = await menuItemsCollection.updateOne(
                {
                    _id: new ObjectId(id),
                },
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


/* ADMIN: DELETE MENU ITEM */

app.delete(
    "/admin/menu-items/:id",
    verifyToken,
    requireRole("admin"),
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
            });

            if (result.deletedCount === 0) {
                return res.status(404).json({
                    message: "Menu item not found",
                });
            }

            res.status(200).json({
                message: "Menu item deleted successfully",
            });
        } catch (error) {
            console.error("Admin Delete Menu Item Error:", error);

            res.status(500).json({
                message: "Failed to delete menu item",
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




/* PUBLIC: GET FEATURED MENU ITEMS */
app.get("/menu-items/featured", async (req, res) => {
    try {
        const menuItems = await menuItemsCollection
            .find({
                status: "approved",
            })
            .sort({ createdAt: -1 })
            .limit(6)
            .toArray();

        const vendorIds = [
            ...new Map(
                menuItems
                    .filter((item) => item.vendorId)
                    .map((item) => [String(item.vendorId), item.vendorId])
            ).values(),
        ];

        const vendors = await usersCollection
            .find({ _id: { $in: vendorIds } })
            .toArray();

        const vendorMap = new Map(
            vendors.map((vendor) => [
                String(vendor._id),
                vendor.businessName || vendor.name || "PizzaHub Vendor",
            ])
        );

        const featuredItems = menuItems.map((item) => ({
            ...item,
            vendor: {
                name: vendorMap.get(String(item.vendorId)) || "PizzaHub Vendor",
            },
        }));

        res.status(200).json(featuredItems);
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

            const createdAt = new Date();

            const newOrder = {
                itemId: menuItem._id,
                vendorId: menuItem.vendorId,
                customerId: req.authUser._id,
                deliveryDate,
                deliveryAddress: deliveryAddress.trim(),
                message: message?.trim() || "",
                status: "pending",
                statusHistory: [
                    {
                        status: "pending",
                        updatedAt: createdAt,
                    },
                ],
                createdAt,
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
                            statusHistory: 1,
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
                    $push: {
                        statusHistory: {
                            status: "cancelled",
                            timestamp: new Date(),
                        },
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
                    $push: {
                        statusHistory: {
                            status,
                            updatedAt: new Date(),
                        },
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

/* PUBLIC: GET MENU ITEMS */
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
            const normalizedCategory = category.trim().toLowerCase();

            if (normalizedCategory === "chicken pizzas") {
                filter.category = {
                    $in: [/^Chicken Pizzas$/i, /^Beef Pizzas$/i],
                };
            } else if (normalizedCategory === "sides & appetizers") {
                filter.category = {
                    $in: [/^Sides & Appetizers$/i, /^Appetizers$/i],
                };
            } else {
                filter.category = {
                    $regex: `^${category.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
                    $options: "i",
                };
            }
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

        // Get unique vendor IDs
        const vendorIds = [
            ...new Map(
                menuItems
                    .filter((item) => item.vendorId)
                    .map((item) => [String(item.vendorId), item.vendorId])
            ).values(),
        ];

        // Fetch vendors
        const vendors = await usersCollection
            .find({ _id: { $in: vendorIds } })
            .toArray();

        // Create vendor name lookup
        const vendorMap = new Map(
            vendors.map((vendor) => [
                String(vendor._id),
                vendor.businessName || vendor.name || "PizzaHub Vendor",
            ])
        );

        // Attach vendor information to menu items
        const menuItemsWithVendors = menuItems.map((item) => ({
            ...item,
            vendor: {
                name: vendorMap.get(String(item.vendorId)) || "PizzaHub Vendor",
            },
        }));

        res.status(200).json(menuItemsWithVendors);
    } catch (error) {
        console.error("Get Public Menu Items Error:", error);

        res.status(500).json({
            message: "Failed to fetch menu items",
        });
    }
});


/* ADMIN: GET ALL TRANSACTIONS */

app.get(
    "/admin/transactions",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { status } = req.query;

            const filter = {};

            if (status) {
                const allowedStatuses = ["pending", "succeeded"];

                if (!allowedStatuses.includes(status)) {
                    return res.status(400).json({
                        message: "Invalid transaction status",
                    });
                }

                filter.status = status;
            }

            const transactions = await transactionsCollection
                .aggregate([
                    {
                        $match: filter,
                    },
                    {
                        $sort: {
                            createdAt: -1,
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
                            vendor: {
                                name: "$vendor.name",
                                email: "$vendor.email",
                                businessName: "$vendor.businessName",
                            },
                            amount: 1,
                            currency: 1,
                            plan: 1,
                            status: 1,
                            createdAt: 1,
                            paidAt: 1,
                        },
                    },
                ])
                .toArray();

            res.status(200).json(transactions);
        } catch (error) {
            console.error("Get Admin Transactions Error:", error);

            res.status(500).json({
                message: "Failed to fetch transactions",
            });
        }
    }
);


/* ADMIN: GET ALL USERS */

app.get(
    "/admin/users",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { role } = req.query;

            const filter = {};

            if (role) {
                const allowedRoles = ["customer", "vendor", "admin"];

                if (!allowedRoles.includes(role)) {
                    return res.status(400).json({
                        message: "Invalid user role",
                    });
                }

                filter.role = role;
            }

            const users = await usersCollection
                .find(filter, {
                    projection: {
                        name: 1,
                        email: 1,
                        image: 1,
                        role: 1,
                        createdAt: 1,
                    },
                })
                .sort({ createdAt: -1 })
                .toArray();

            res.status(200).json(users);
        } catch (error) {
            console.error("Get Admin Users Error:", error);

            res.status(500).json({
                message: "Failed to fetch users",
            });
        }
    }
);

/* ADMIN: GET DASHBOARD STATISTICS */

app.get(
    "/admin/dashboard/stats",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const [
                totalUsers,
                totalCustomers,
                totalVendors,
                totalMenuItems,
                pendingMenuItems,
                approvedMenuItems,
                totalOrders,
                pendingOrders,
                acceptedOrders,
                rejectedOrders,
                cancelledOrders,
                recentOrders,
            ] = await Promise.all([
                usersCollection.countDocuments(),
                usersCollection.countDocuments({ role: "customer" }),
                usersCollection.countDocuments({ role: "vendor" }),
                menuItemsCollection.countDocuments(),
                menuItemsCollection.countDocuments({ status: "pending" }),
                menuItemsCollection.countDocuments({ status: "approved" }),
                ordersCollection.countDocuments(),
                ordersCollection.countDocuments({ status: "pending" }),
                ordersCollection.countDocuments({ status: "accepted" }),
                ordersCollection.countDocuments({ status: "rejected" }),
                ordersCollection.countDocuments({ status: "cancelled" }),

                ordersCollection.aggregate([
                    { $sort: { createdAt: -1 } },
                    { $limit: 5 },
                    {
                        $lookup: {
                            from: "menuItems",
                            localField: "itemId",
                            foreignField: "_id",
                            as: "item",
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
                        $lookup: {
                            from: "user",
                            localField: "vendorId",
                            foreignField: "_id",
                            as: "vendor",
                        },
                    },
                    {
                        $project: {
                            status: 1,
                            createdAt: 1,
                            itemName: {
                                $ifNull: [
                                    { $arrayElemAt: ["$item.itemName", 0] },
                                    "Menu item unavailable",
                                ],
                            },
                            customerName: {
                                $ifNull: [
                                    { $arrayElemAt: ["$customer.name", 0] },
                                    "Unknown Customer",
                                ],
                            },
                            vendorName: {
                                $ifNull: [
                                    { $arrayElemAt: ["$vendor.businessName", 0] },
                                    {
                                        $ifNull: [
                                            { $arrayElemAt: ["$vendor.name", 0] },
                                            "Unknown Vendor",
                                        ],
                                    },
                                ],
                            },
                        },
                    },
                ]).toArray(),
            ]);

            res.status(200).json({
                stats: {
                    totalUsers,
                    totalCustomers,
                    totalVendors,
                    totalMenuItems,
                    pendingMenuItems,
                    approvedMenuItems,
                    totalOrders,
                    pendingOrders,
                    acceptedOrders,
                    rejectedOrders,
                    cancelledOrders,
                },
                recentOrders,
            });
        } catch (error) {
            console.error("Get Admin Dashboard Stats Error:", error);

            res.status(500).json({
                message: "Failed to fetch dashboard statistics",
            });
        }
    }
);


/* PROFILE: GET CURRENT USER PROFILE */

app.get("/profile", verifyToken, async (req, res) => {
    try {
        const {
            name,
            email,
            image,
            role,
            businessName,
            subscriptionPlan,
            subscriptionExpiresAt,
        } = req.authUser;

        res.status(200).json({
            name,
            email,
            image: image || "",
            role,
            businessName: businessName || "",
            subscriptionPlan: subscriptionPlan || "free",
            subscriptionExpiresAt: subscriptionExpiresAt || null,
        });
    } catch (error) {
        console.error("Get Profile Error:", error);

        res.status(500).json({
            message: "Failed to fetch profile",
        });
    }
});

/* VENDOR: UPDATE BUSINESS NAME */

app.patch(
    "/profile/business-name",
    verifyToken,
    requireRole("vendor"),
    async (req, res) => {
        try {
            const { businessName } = req.body;

            if (
                typeof businessName !== "string" ||
                !businessName.trim()
            ) {
                return res.status(400).json({
                    message: "Business name is required",
                });
            }

            if (businessName.trim().length > 100) {
                return res.status(400).json({
                    message: "Business name must be 100 characters or fewer",
                });
            }

            await usersCollection.updateOne(
                { _id: req.authUser._id },
                {
                    $set: {
                        businessName: businessName.trim(),
                        updatedAt: new Date(),
                    },
                }
            );

            res.status(200).json({
                message: "Business name updated successfully",
                businessName: businessName.trim(),
            });
        } catch (error) {
            console.error("Update Business Name Error:", error);

            res.status(500).json({
                message: "Failed to update business name",
            });
        }
    }
);

/* VENDOR: CREATE PREMIUM SUBSCRIPTION CHECKOUT */

app.post(
    "/vendor/subscription/checkout",
    verifyToken,
    requireRole("vendor"),
    async (req, res) => {
        try {
            const clientUrl = process.env.CLIENT_URL;

            if (!clientUrl) {
                return res.status(500).json({
                    message: "Client URL is not configured",
                });
            }

            // Prevent duplicate subscription checkout for active Premium vendors
            const isPremiumActive =
                req.authUser.subscriptionPlan === "premium" &&
                req.authUser.subscriptionExpiresAt &&
                new Date(req.authUser.subscriptionExpiresAt) > new Date();

            if (isPremiumActive) {
                return res.status(400).json({
                    message: "You already have an active Premium subscription",
                });
            }

            // Create Stripe Checkout Session
            const session = await stripe.checkout.sessions.create({
                mode: "subscription",

                customer_email: req.authUser.email,

                client_reference_id: String(req.authUser._id),

                line_items: [
                    {
                        price_data: {
                            currency: "usd",
                            product_data: {
                                name: "PizzaHub Premium Vendor Plan",
                                description: "Unlimited active menu items",
                            },
                            unit_amount: 999,
                            recurring: {
                                interval: "month",
                            },
                        },
                        quantity: 1,
                    },
                ],

                metadata: {
                    vendorId: String(req.authUser._id),
                    plan: "premium",
                },

                subscription_data: {
                    metadata: {
                        vendorId: String(req.authUser._id),
                        plan: "premium",
                    },
                },

                success_url: `${clientUrl}/dashboard/vendor/subscription/success?session_id={CHECKOUT_SESSION_ID}`,

                cancel_url: `${clientUrl}/dashboard/vendor/subscription/cancel`,
            });

            // Save pending transaction
            await transactionsCollection.insertOne({
                vendorId: req.authUser._id,
                stripeSessionId: session.id,
                amount: 9.99,
                currency: "usd",
                plan: "premium",
                status: "pending",
                createdAt: new Date(),
            });

            res.status(200).json({
                message: "Checkout session created successfully",
                url: session.url,
            });
        } catch (error) {
            console.error("Create Subscription Checkout Error:", error);

            res.status(500).json({
                message: "Failed to create subscription checkout",
            });
        }
    }
);



/* VENDOR: VERIFY PREMIUM SUBSCRIPTION PAYMENT */

app.post(
    "/vendor/subscription/verify",
    verifyToken,
    requireRole("vendor"),
    async (req, res) => {
        try {
            const { sessionId } = req.body;

            if (!sessionId || typeof sessionId !== "string") {
                return res.status(400).json({
                    success: false,
                    message: "Checkout session ID is required",
                });
            }

            // Retrieve the Checkout Session from Stripe
            const session = await stripe.checkout.sessions.retrieve(
                sessionId
            );

            const vendorId = String(req.authUser._id);

            // Verify Checkout Session
            if (
                session.status !== "complete" ||
                !["paid", "no_payment_required"].includes(
                    session.payment_status
                ) ||
                session.mode !== "subscription"
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Payment verification failed",
                });
            }

            // Verify vendor ownership
            if (
                session.metadata?.vendorId !== vendorId ||
                session.metadata?.plan !== "premium" ||
                session.client_reference_id !== vendorId
            ) {
                return res.status(403).json({
                    success: false,
                    message: "Invalid subscription ownership",
                });
            }

            // Check whether the verified webhook processed this transaction
            const transaction = await transactionsCollection.findOne({
                stripeSessionId: session.id,
                vendorId: req.authUser._id,
                status: "succeeded",
            });

            if (!transaction) {
                return res.status(200).json({
                    success: false,
                    pending: true,
                    message:
                        "Payment received. Waiting for Stripe webhook confirmation.",
                });
            }

            // Confirm that Premium was activated by the webhook
            const vendor = await usersCollection.findOne({
                _id: req.authUser._id,
                role: "vendor",
                subscriptionPlan: "premium",
                stripeSubscriptionId: transaction.stripeSubscriptionId,
                subscriptionExpiresAt: { $gt: new Date() },
            });

            if (!vendor) {
                return res.status(200).json({
                    success: false,
                    pending: true,
                    message:
                        "Waiting for Premium subscription activation.",
                });
            }

            return res.status(200).json({
                success: true,
                message: "Premium subscription verified successfully",
                subscriptionPlan: vendor.subscriptionPlan,
                subscriptionExpiresAt: vendor.subscriptionExpiresAt,
            });
        } catch (error) {
            console.error("Verify Subscription Error:", error);

            return res.status(500).json({
                success: false,
                message: "Failed to verify subscription payment",
            });
        }
    }
);


// Start Server
app.listen(port, () => {
    console.log(`PizzaHub server is running on port ${port}`);
});