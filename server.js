const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

/* ==========================================
   MIDDLEWARE
========================================== */

app.use(cors());
app.use(express.json());

/* ==========================================
   FIREBASE ADMIN INITIALIZATION
========================================== */

if (!admin.apps.length) {
  try {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
      console.error("FIREBASE_SERVICE_ACCOUNT environment variable is missing.");
      process.exit(1);
    }

    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });

    console.log("Firebase Admin initialized successfully.");
  } catch (error) {
    console.error("Firebase Admin initialization error:", error.message);
    process.exit(1);
  }
}

const db = admin.firestore();

/* ==========================================
   CONSTANTS & HELPERS
========================================== */

const KSH_PER_POINT = 10; // Earn 1 point per 10 KSh on final fare

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  try {
    const parts = storedPassword.split(":");
    if (parts.length !== 2) return false;
    const salt = parts[0];
    const storedHash = parts[1];
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash, "hex"));
  } catch {
    return false;
  }
}

/* ==========================================
   AUTHENTICATION MIDDLEWARE
========================================== */

async function verifyFirebaseToken(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Authentication token required." });
    }
    const token = header.substring(7);
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

async function requireModerator(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Moderator authentication required." });
    }
    const token = header.substring(7);
    const decodedToken = await admin.auth().verifyIdToken(token);

    if (decodedToken.admin !== true && decodedToken.role !== "admin") {
      return res.status(403).json({ error: "Moderator authorization required." });
    }
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Moderator auth failed:", error.message);
    return res.status(403).json({ error: "Unauthorized moderator." });
  }
}

/* ==========================================
   HEALTH CHECK
========================================== */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    service: "Amir Chap Chap Logistics API",
    timestamp: new Date().toISOString()
  });
});

/* ==========================================
   CUSTOMER ROUTES
========================================== */

app.post("/api/customer/register", verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const email = req.body.email || req.user.email || "";
    const phone = req.body.phone || req.body.whatsapp || "";

    await db.collection("users").doc(uid).set(
      {
        uid,
        email,
        phone,
        role: "customer",
        points: 0,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    res.status(200).json({ message: "Customer profile registered." });
  } catch (error) {
    console.error("Customer register error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ==========================================
   RIDER MANAGEMENT & AUTH (MODERATOR & RIDER)
========================================== */

app.post("/api/moderator/riders", requireModerator, async (req, res) => {
  try {
    const { jobId, name, phone, whatsapp, nationalId, bikeType, bikeModel, password, status } = req.body;

    if (!jobId || !name || !password) {
      return res.status(400).json({ error: "Rider Job ID, name, and password are required." });
    }

    const cleanJobId = String(jobId).trim().toUpperCase();

    const riderQuery = await db.collection("riders").where("jobId", "==", cleanJobId).limit(1).get();
    if (!riderQuery.empty) {
      return res.status(409).json({ error: "Rider Job ID already exists." });
    }

    const internalEmail = `${cleanJobId.toLowerCase()}@rider.amirchapchap.local`;
    const userRecord = await admin.auth().createUser({
      email: internalEmail,
      password: crypto.randomBytes(32).toString("hex"),
      displayName: name
    });

    await admin.auth().setCustomUserClaims(userRecord.uid, { role: "rider" });

    const passwordHash = hashPassword(password);
    const initialStatus = status || "active";

    const riderData = {
      uid: userRecord.uid,
      jobId: cleanJobId,
      name: String(name).trim(),
      phone: phone || "",
      whatsapp: whatsapp || "",
      nationalId: nationalId || "",
      bikeType: bikeType || "",
      bikeModel: bikeModel || "",
      passwordHash,
      status: initialStatus,
      availabilityStatus: initialStatus === "active" ? "available" : "offline",
      role: "rider",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await db.collection("riders").doc(userRecord.uid).set(riderData);

    await db.collection("users").doc(userRecord.uid).set({
      uid: userRecord.uid,
      jobId: cleanJobId,
      name: String(name).trim(),
      phone: phone || "",
      whatsapp: whatsapp || "",
      role: "rider",
      status: initialStatus,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({
      message: "Rider created successfully.",
      rider: {
        uid: userRecord.uid,
        jobId: cleanJobId,
        name: String(name).trim(),
        phone: phone || "",
        whatsapp: whatsapp || "",
        status: initialStatus,
        availabilityStatus: initialStatus === "active" ? "available" : "offline"
      }
    });
  } catch (error) {
    console.error("Error registering rider:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/rider-login", async (req, res) => {
  try {
    const { jobId, password } = req.body;

    if (!jobId || !password) {
      return res.status(400).json({ error: "Job ID and password required." });
    }

    const cleanJobId = String(jobId).trim().toUpperCase();
    const snapshot = await db.collection("riders").where("jobId", "==", cleanJobId).limit(1).get();

    if (snapshot.empty) {
      return res.status(401).json({ error: "Invalid Rider Job ID or password." });
    }

    const doc = snapshot.docs[0];
    const rider = doc.data();

    if (rider.status !== "active") {
      return res.status(403).json({ error: "Rider account is inactive." });
    }

    if (!rider.passwordHash || !verifyPassword(password, rider.passwordHash)) {
      return res.status(401).json({ error: "Invalid Rider Job ID or password." });
    }

    const customToken = await admin.auth().createCustomToken(rider.uid, {
      role: "rider",
      jobId: rider.jobId
    });

    res.status(200).json({
      message: "Login successful.",
      token: customToken,
      rider: {
        uid: rider.uid,
        jobId: rider.jobId,
        name: rider.name,
        phone: rider.phone || "",
        whatsapp: rider.whatsapp || "",
        status: rider.status,
        availabilityStatus: rider.availabilityStatus || "available"
      }
    });
  } catch (error) {
    console.error("Rider login error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/moderator/riders", requireModerator, async (req, res) => {
  try {
    const snapshot = await db.collection("riders").get();
    const riders = snapshot.docs.map((doc) => {
      const data = doc.data();
      delete data.passwordHash;
      return { id: doc.id, ...data };
    });

    // Priority sorting: Available (1), Busy (2), Inactive/Offline (3)
    riders.sort((a, b) => {
      const priority = { available: 1, busy: 2, offline: 3 };
      const statusA = a.status === "inactive" ? "offline" : a.availabilityStatus || "available";
      const statusB = b.status === "inactive" ? "offline" : b.availabilityStatus || "available";
      return (priority[statusA] || 4) - (priority[statusB] || 4);
    });

    res.status(200).json({ riders });
  } catch (error) {
    console.error("Error fetching riders:", error);
    res.status(500).json({ error: error.message });
  }
});

app.patch("/api/moderator/riders/:uid/status", requireModerator, async (req, res) => {
  try {
    const uid = req.params.uid;
    const { status } = req.body;

    if (status !== "active" && status !== "inactive") {
      return res.status(400).json({ error: "Status must be 'active' or 'inactive'." });
    }

    const availabilityStatus = status === "active" ? "available" : "offline";

    await db.collection("riders").doc(uid).update({
      status,
      availabilityStatus
    });

    await db.collection("users").doc(uid).set({ status }, { merge: true });
    await admin.auth().updateUser(uid, { disabled: status !== "active" });

    res.status(200).json({ message: `Rider status set to ${status}.` });
  } catch (error) {
    console.error("Error updating rider status:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/moderator/riders/:uid", requireModerator, async (req, res) => {
  try {
    const uid = req.params.uid;
    await admin.auth().deleteUser(uid);
    await db.collection("riders").doc(uid).delete();
    await db.collection("users").doc(uid).delete();
    res.status(200).json({ message: "Rider deleted successfully." });
  } catch (error) {
    console.error("Error deleting rider:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ==========================================
   ORDER MODERATION & FARE MANAGEMENT
========================================== */

app.get("/api/moderator/orders", requireModerator, async (req, res) => {
  try {
    const snapshot = await db.collection("orders").orderBy("createdAt", "desc").get();
    const orders = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.status(200).json({ orders });
  } catch (error) {
    console.error("Error loading orders:", error);
    res.status(500).json({ error: error.message });
  }
});

// Set Fares: Original Fare + Transport Charge = Final Fare
app.patch("/api/moderator/orders/:orderId/fare", requireModerator, async (req, res) => {
  try {
    const { originalFare, transportCharge } = req.body;
    const baseFare = Number(originalFare) || 0;
    const charge = Number(transportCharge) || 0;
    const finalFare = baseFare + charge;

    const orderRef = db.collection("orders").doc(req.params.orderId);
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) {
      return res.status(404).json({ error: "Order not found." });
    }

    await orderRef.update({
      originalFare: baseFare,
      transportCharge: charge,
      finalFare: finalFare,
      fareUpdatedBy: req.user.uid,
      fareUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({ message: "Fare updated successfully.", finalFare });
  } catch (error) {
    console.error("Error updating fare:", error);
    res.status(500).json({ error: error.message });
  }
});

// Assign Rider to Order
app.patch("/api/moderator/orders/:orderId/assign-rider", requireModerator, async (req, res) => {
  try {
    const { riderUid } = req.body;
    const orderRef = db.collection("orders").doc(req.params.orderId);

    const [orderSnap, riderSnap] = await Promise.all([
      orderRef.get(),
      db.collection("riders").doc(riderUid).get()
    ]);

    if (!orderSnap.exists) return res.status(404).json({ error: "Order not found." });
    if (!riderSnap.exists) return res.status(404).json({ error: "Rider not found." });

    const riderData = riderSnap.data();

    await orderRef.update({
      riderUid,
      riderName: riderData.name || "",
      riderPhone: riderData.phone || "",
      status: "assigned",
      assignedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Set Rider to Busy
    await db.collection("riders").doc(riderUid).update({
      availabilityStatus: "busy"
    });

    // Create Notification
    await db.collection("notifications").add({
      riderUid,
      orderId: req.params.orderId,
      title: "New Job Assigned",
      message: `Assigned to order #${req.params.orderId}`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      read: false
    });

    res.status(200).json({ message: "Rider assigned successfully." });
  } catch (error) {
    console.error("Error assigning rider:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ==========================================
   RIDER ORDER PROGRESSION
========================================== */

app.get("/api/rider/jobs", verifyFirebaseToken, async (req, res) => {
  try {
    if (req.user.role !== "rider") {
      return res.status(403).json({ error: "Rider authorization required." });
    }

    const snapshot = await db.collection("orders").where("riderUid", "==", req.user.uid).get();
    const orders = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    res.status(200).json({ orders });
  } catch (error) {
    console.error("Error loading rider jobs:", error);
    res.status(500).json({ error: error.message });
  }
});

// 1. Pickup Order
app.patch("/api/rider/orders/:orderId/pickup", verifyFirebaseToken, async (req, res) => {
  try {
    const orderRef = db.collection("orders").doc(req.params.orderId);
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) return res.status(404).json({ error: "Order not found." });
    if (orderSnap.data().riderUid !== req.user.uid) {
      return res.status(403).json({ error: "Unauthorized for this order." });
    }

    await orderRef.update({
      status: "picked_up",
      pickedUpAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({ message: "Order status updated to picked_up." });
  } catch (error) {
    console.error("Error updating pickup status:", error);
    res.status(500).json({ error: error.message });
  }
});

// 2. Start Delivery (In Transit)
app.patch("/api/rider/orders/:orderId/start-delivery", verifyFirebaseToken, async (req, res) => {
  try {
    const orderRef = db.collection("orders").doc(req.params.orderId);
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) return res.status(404).json({ error: "Order not found." });
    if (orderSnap.data().riderUid !== req.user.uid) {
      return res.status(403).json({ error: "Unauthorized for this order." });
    }

    await orderRef.update({
      status: "in_transit",
      inTransitAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).json({ message: "Order status updated to in_transit." });
  } catch (error) {
    console.error("Error updating transit status:", error);
    res.status(500).json({ error: error.message });
  }
});

// 3. Complete Delivery & Award Points
app.patch("/api/rider/orders/:orderId/delivered", verifyFirebaseToken, async (req, res) => {
  try {
    const orderRef = db.collection("orders").doc(req.params.orderId);

    await db.runTransaction(async (transaction) => {
      const orderDoc = await transaction.get(orderRef);

      if (!orderDoc.exists) throw new Error("Order not found.");

      const orderData = orderDoc.data();

      if (orderData.riderUid !== req.user.uid) {
        throw new Error("Unauthorized for this order.");
      }

      if (orderData.pointsAwarded) {
        throw new Error("Points have already been awarded for this order.");
      }

      const customerUid = orderData.userId || orderData.customerUid;
      const fareToCalculate = orderData.finalFare || orderData.originalFare || 0;
      const pointsEarned = Math.floor(fareToCalculate / KSH_PER_POINT);

      // Update Order
      transaction.update(orderRef, {
        status: "delivered",
        deliveredAt: admin.firestore.FieldValue.serverTimestamp(),
        pointsAwarded: true,
        pointsEarned
      });

      // Award Loyalty Points to Customer
      if (customerUid) {
        const customerRef = db.collection("users").doc(customerUid);
        transaction.set(
          customerRef,
          { points: admin.firestore.FieldValue.increment(pointsEarned) },
          { merge: true }
        );
      }

      // Set Rider Back to Available
      const riderRef = db.collection("riders").doc(req.user.uid);
      transaction.update(riderRef, { availabilityStatus: "available" });
    });

    res.status(200).json({ message: "Delivery completed successfully." });
  } catch (error) {
    console.error("Error marking delivery as complete:", error.message);
    res.status(400).json({ error: error.message });
  }
});

/* ==========================================
   START SERVER
========================================== */

app.listen(PORT, () => {
  console.log(`Amir Chap Chap Server listening on port ${PORT}`);
});
