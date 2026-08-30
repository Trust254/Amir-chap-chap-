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
   FIREBASE ADMIN
========================================== */

if (!admin.apps.length) {
  try {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
      console.error("FIREBASE_SERVICE_ACCOUNT is missing.");
      process.exit(1);
    }

    const serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT
    );

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });

    console.log("Firebase Admin initialized successfully.");
  } catch (error) {
    console.error(
      "Firebase Admin initialization error:",
      error.message
    );
    process.exit(1);
  }
}

const db = admin.firestore();

/* ==========================================
   PASSWORD HASHING
========================================== */

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  try {
    const parts = storedPassword.split(":");

    if (parts.length !== 2) return false;

    const salt = parts[0];
    const storedHash = parts[1];

    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
    return false;
  }
}

/* ==========================================
   AUTHENTICATION HELPERS
========================================== */

async function verifyFirebaseToken(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication token required."
      });
    }

    const token = header.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);

    return res.status(401).json({
      error: "Invalid or expired authentication token."
    });
  }
}

async function requireModerator(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Moderator authentication required."
      });
    }

    const token = header.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    if (decodedToken.admin !== true) {
      return res.status(403).json({
        error: "Moderator authorization required."
      });
    }

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error(
      "Moderator authentication failed:",
      error.message
    );

    return res.status(403).json({
      error: "Unauthorized moderator."
    });
  }
}

/* ==========================================
   HEALTH CHECK
========================================== */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    message: "Amir Chap Chap Backend is running smoothly.",
    timestamp: new Date().toISOString()
  });
});

/* ==========================================
   RIDER TEST
========================================== */

app.get("/api/moderator/riders/test", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Rider route is deployed"
  });
});

/* ==========================================
   CUSTOMER REGISTER
========================================== */

app.post(
  "/api/customer/register",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const email = req.body.email || req.user.email || "";

      await db.collection("users").doc(uid).set(
        {
          uid,
          email,
          role: "customer",
          points: 0,
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

      res.status(200).json({
        message: "Customer registered successfully."
      });
    } catch (error) {
      console.error(
        "Customer registration error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   CREATE RIDER
========================================== */

app.post(
  "/api/moderator/riders",
  requireModerator,
  async (req, res) => {
    try {
      const {
        jobId,
        name,
        phone,
        whatsapp,
        nationalId,
        bikeType,
        bikeModel,
        password,
        status
      } = req.body;

      if (!jobId || !name || !password) {
        return res.status(400).json({
          error:
            "Rider Job ID, name and password are required."
        });
      }

      const cleanJobId =
        String(jobId).trim().toUpperCase();

      const riderQuery =
        await db
          .collection("riders")
          .where("jobId", "==", cleanJobId)
          .limit(1)
          .get();

      if (!riderQuery.empty) {
        return res.status(409).json({
          error: "This Rider Job ID already exists."
        });
      }

      /*
        Create a Firebase Auth account using an internal
        email address. Riders don't need to see this email.
      */

      const internalEmail =
        `${cleanJobId.toLowerCase()}@rider.amirchapchap.local`;

      const userRecord =
        await admin.auth().createUser({
          email: internalEmail,
          password:
            crypto.randomBytes(32).toString("hex"),
          displayName: name
        });

      /*
        Rider gets a custom Firebase claim.
      */

      await admin.auth().setCustomUserClaims(
        userRecord.uid,
        {
          role: "rider"
        }
      );

      const passwordHash =
        hashPassword(password);

      const rider = {
        uid: userRecord.uid,
        jobId: cleanJobId,
        name: String(name).trim(),
        phone: phone || "",
        whatsapp: whatsapp || "",
        nationalId: nationalId || "",
        bikeType: bikeType || "",
        bikeModel: bikeModel || "",
        passwordHash,
        status: status || "active",
        role: "rider",
        createdAt:
          admin.firestore.FieldValue.serverTimestamp()
      };

      await db
        .collection("riders")
        .doc(userRecord.uid)
        .set(rider);

      /*
        Also create/update the users record.
      */

      await db
        .collection("users")
        .doc(userRecord.uid)
        .set({
          uid: userRecord.uid,
          jobId: cleanJobId,
          name: String(name).trim(),
          phone: phone || "",
          whatsapp: whatsapp || "",
          role: "rider",
          status: status || "active",
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      res.status(201).json({
        message: "Rider registered successfully.",
        rider: {
          uid: userRecord.uid,
          jobId: cleanJobId,
          name: String(name).trim(),
          phone: phone || "",
          whatsapp: whatsapp || "",
          bikeType: bikeType || "",
          bikeModel: bikeModel || "",
          status: status || "active"
        }
      });
    } catch (error) {
      console.error(
        "Error creating rider:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   RIDER LOGIN
========================================== */

app.post("/api/rider-login", async (req, res) => {
  try {
    const {
      jobId,
      password
    } = req.body;

    if (!jobId || !password) {
      return res.status(400).json({
        error:
          "Rider Job ID and password are required."
      });
    }

    const cleanJobId =
      String(jobId).trim().toUpperCase();

    const snapshot =
      await db
        .collection("riders")
        .where("jobId", "==", cleanJobId)
        .limit(1)
        .get();

    if (snapshot.empty) {
      return res.status(401).json({
        error: "Invalid Rider Job ID or password."
      });
    }

    const doc = snapshot.docs[0];
    const rider = doc.data();

    if (rider.status !== "active") {
      return res.status(403).json({
        error:
          "This rider account is not active."
      });
    }

    if (
      !rider.passwordHash ||
      !verifyPassword(
        password,
        rider.passwordHash
      )
    ) {
      return res.status(401).json({
        error: "Invalid Rider Job ID or password."
      });
    }

    /*
      Create a Firebase custom token.
      The frontend can use the returned token later
      if Firebase authentication is needed.
    */

    const customToken =
      await admin
        .auth()
        .createCustomToken(
          rider.uid,
          {
            role: "rider",
            jobId: rider.jobId
          }
        );

    res.status(200).json({
      message: "Rider login successful.",
      token: customToken,
      rider: {
        uid: rider.uid,
        jobId: rider.jobId,
        name: rider.name,
        phone: rider.phone || "",
        whatsapp: rider.whatsapp || "",
        bikeType: rider.bikeType || "",
        bikeModel: rider.bikeModel || "",
        status: rider.status
      }
    });
  } catch (error) {
    console.error(
      "Rider login error:",
      error
    );

    res.status(500).json({
      error: error.message
    });
  }
});

/* ==========================================
   GET ALL RIDERS
========================================== */

app.get(
  "/api/moderator/riders",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("riders")
          .orderBy("createdAt", "desc")
          .get();

      const riders =
        snapshot.docs.map(doc => {
          const data = doc.data();

          /*
            Never send the password hash to the frontend.
          */

          delete data.passwordHash;

          return {
            id: doc.id,
            ...data
          };
        });

      res.status(200).json({
        riders
      });
    } catch (error) {
      console.error(
        "Error fetching riders:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   CHANGE RIDER STATUS
========================================== */

app.patch(
  "/api/moderator/riders/:uid/status",
  requireModerator,
  async (req, res) => {
    try {
      const uid = req.params.uid;
      const { status } = req.body;

      if (
        status !== "active" &&
        status !== "inactive"
      ) {
        return res.status(400).json({
          error:
            "Status must be active or inactive."
        });
      }

      await db
        .collection("riders")
        .doc(uid)
        .update({
          status
        });

      await db
        .collection("users")
        .doc(uid)
        .set(
          {
            status
          },
          { merge: true }
        );

      /*
        Disable/enable the Firebase Auth account too.
      */

      await admin.auth().updateUser(uid, {
        disabled: status !== "active"
      });

      res.status(200).json({
        message:
          `Rider status changed to ${status}.`
      });
    } catch (error) {
      console.error(
        "Error changing rider status:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   DELETE RIDER
========================================== */

app.delete(
  "/api/moderator/riders/:uid",
  requireModerator,
  async (req, res) => {
    try {
      const uid = req.params.uid;

      await admin.auth().deleteUser(uid);

      await db
        .collection("riders")
        .doc(uid)
        .delete();

      await db
        .collection("users")
        .doc(uid)
        .delete();

      res.status(200).json({
        message:
          "Rider removed successfully."
      });
    } catch (error) {
      console.error(
        "Error removing rider:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   GET CUSTOMERS
========================================== */

app.get(
  "/api/moderator/customers",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("users")
          .where("role", "==", "customer")
          .get();

      const customers =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.status(200).json({
        customers
      });
    } catch (error) {
      console.error(
        "Error loading customers:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   GET ALL ORDERS
========================================== */

app.get(
  "/api/moderator/orders",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("orders")
          .orderBy("createdAt", "desc")
          .get();

      const orders =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.status(200).json({
        orders
      });
    } catch (error) {
      console.error(
        "Error loading orders:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   APPROVE ORDER
========================================== */

app.patch(
  "/api/moderator/orders/:orderId/approve",
  requireModerator,
  async (req, res) => {
    try {
      const orderId =
        req.params.orderId;

      const orderRef =
        db.collection("orders").doc(orderId);

      const orderSnapshot =
        await orderRef.get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      await orderRef.update({
        status: "approved",
        approvedAt:
          admin.firestore.FieldValue.serverTimestamp(),
        approvedBy: req.user.uid
      });

      res.status(200).json({
        message:
          "Order approved successfully."
      });
    } catch (error) {
      console.error(
        "Error approving order:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   RIDER JOBS
========================================== */

app.get(
  "/api/rider/jobs",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      if (req.user.role !== "rider") {
        return res.status(403).json({
          error: "Rider access required."
        });
      }

      const snapshot =
        await db
          .collection("orders")
          .where(
            "riderUid",
            "==",
            req.user.uid
          )
          .get();

      const orders =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.status(200).json({
        orders
      });
    } catch (error) {
      console.error(
        "Error loading rider jobs:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   RIDER NOTIFICATIONS
========================================== */

app.get(
  "/api/rider/notifications",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      if (req.user.role !== "rider") {
        return res.status(403).json({
          error: "Rider access required."
        });
      }

      const snapshot =
        await db
          .collection("notifications")
          .where(
            "riderUid",
            "==",
            req.user.uid
          )
          .get();

      const notifications =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.status(200).json({
        notifications
      });
    } catch (error) {
      console.error(
        "Error loading notifications:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   START SERVER
========================================== */

app.listen(PORT, () => {
  console.log(
    `Amir Chap Chap Backend LIVE on port ${PORT}`
  );
});
