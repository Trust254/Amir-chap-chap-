const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 10000;

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(cors());
app.use(express.json());

/* =========================================================
   FIREBASE ADMIN
========================================================= */

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("FIREBASE_SERVICE_ACCOUNT is missing.");
  process.exit(1);
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT
  );
} catch (error) {
  console.error("FIREBASE_SERVICE_ACCOUNT is not valid JSON.");
  process.exit(1);
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("Firebase Admin initialized successfully.");
} catch (error) {
  console.error("Error initializing Firebase Admin:", error.message);
}

const db = admin.firestore();

/* =========================================================
   HEALTH CHECK / ROOT ROUTE
========================================================= */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    message: "Amir Chap Chap Backend is running smoothly.",
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   RIDER TEST ROUTE
========================================================= */

app.get("/api/moderator/riders/test", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Rider route is deployed"
  });
});

/* =========================================================
   MODERATOR RIDER ROUTES
========================================================= */

app.get("/api/moderator/riders", async (req, res) => {
  try {
    const snapshot = await db.collection("users").where("role", "==", "rider").get();
    const riders = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(riders);
  } catch (error) {
    console.error("Error fetching riders:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/moderator/riders", async (req, res) => {
  try {
    const { action, uid, email, password, displayName, phoneNumber } = req.body;

    if (action === "create") {
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
      }

      const userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: displayName || "",
        phoneNumber: phoneNumber || undefined
      });

      await admin.auth().setCustomUserClaims(userRecord.uid, { role: "rider" });

      await db.collection("users").doc(userRecord.uid).set({
        uid: userRecord.uid,
        email,
        displayName: displayName || "",
        phoneNumber: phoneNumber || "",
        role: "rider",
        status: "active",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

      return res.status(201).json({
        message: "Rider created successfully",
        uid: userRecord.uid
      });
    }

    if (!uid) {
      return res.status(400).json({ error: "Rider UID is required." });
    }

    if (action === "disable") {
      await admin.auth().updateUser(uid, { disabled: true });
      await db.collection("users").doc(uid).update({ status: "disabled" });
      return res.status(200).json({ message: "Rider account disabled successfully." });
    }

    if (action === "enable") {
      await admin.auth().updateUser(uid, { disabled: false });
      await db.collection("users").doc(uid).update({ status: "active" });
      return res.status(200).json({ message: "Rider account enabled successfully." });
    }

    if (action === "delete") {
      await admin.auth().deleteUser(uid);
      await db.collection("users").doc(uid).delete();
      return res.status(200).json({ message: "Rider account deleted successfully." });
    }

    return res.status(400).json({ error: "Invalid action specified." });
  } catch (error) {
    console.error("Error managing rider:", error);
    res.status(500).json({ error: error.message });
  }
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log(`Amir Chap Chap Backend LIVE on port ${PORT}`);
});
