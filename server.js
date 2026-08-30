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
   FIREBASE ADMIN INITIALIZATION
========================================================= */

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("FIREBASE_SERVICE_ACCOUNT is missing.");
  process.exit(1);
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
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
  console.error(
    "Firebase Admin initialization error:",
    error.message
  );

  process.exit(1);
}

const db = admin.firestore();

/* =========================================================
   HELPERS
========================================================= */

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

/* =========================================================
   AUTHORIZATION
========================================================= */

async function requireModerator(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Moderator authentication token is required."
      });
    }

    const token = header.substring(7);

    const decoded = await admin.auth().verifyIdToken(token);

    if (decoded.admin !== true) {
      return res.status(403).json({
        error: "Moderator authorization required."
      });
    }

    req.user = decoded;
    next();

  } catch (error) {
    console.error("Moderator authentication error:", error.message);

    return res.status(401).json({
      error: "Invalid or expired authentication token."
    });
  }
}

/* =========================================================
   HEALTH CHECK
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
   RIDER LOGIN
   Rider enters:
   ACC-1235 + password
========================================================= */

app.post("/api/rider-login", async (req, res) => {
  try {
    const jobId = clean(req.body.jobId).toUpperCase();
    const password = req.body.password || "";

    if (!jobId || !password) {
      return res.status(400).json({
        error: "Rider Job ID and password are required."
      });
    }

    const snapshot = await db
      .collection("riders")
      .where("jobId", "==", jobId)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(401).json({
        error: "Rider Job ID or password is incorrect."
      });
    }

    const doc = snapshot.docs[0];
    const rider = {
      uid: doc.id,
      ...doc.data()
    };

    if (rider.status !== "active") {
      return res.status(403).json({
        error: "This rider account is not active."
      });
    }

    /*
      Rider Firebase Auth accounts use an internal email
      generated from the Rider Job ID.
    */

    const riderEmail =
      jobId.toLowerCase() + "@riders.amirchapchap.local";

    /*
      Firebase Identity Toolkit REST API is used only
      to verify the rider's password.
    */

    const apiKey = process.env.FIREBASE_WEB_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        error: "FIREBASE_WEB_API_KEY is not configured on the backend."
      });
    }

    const response = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" +
      encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email: riderEmail,
          password: password,
          returnSecureToken: true
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return res.status(401).json({
        error: "Rider Job ID or password is incorrect."
      });
    }

    return res.status(200).json({
      message: "Rider login successful.",
      token: result.idToken,
      rider: {
        uid: rider.uid,
        jobId: rider.jobId || "",
        name: rider.name || "",
        phone: rider.phone || "",
        whatsapp: rider.whatsapp || "",
        nationalId: rider.nationalId || "",
        bikeType: rider.bikeType || "",
        bikeModel: rider.bikeModel || "",
        status: rider.status || "active"
      }
    });

  } catch (error) {
    console.error("Rider login error:", error);

    return res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   MODERATOR - GET RIDERS
========================================================= */

app.get(
  "/api/moderator/riders",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot = await db
        .collection("riders")
        .orderBy("createdAt", "desc")
        .get();

      const riders = snapshot.docs.map(doc => ({
        uid: doc.id,
        ...doc.data()
      }));

      return res.status(200).json({
        riders
      });

    } catch (error) {
      console.error("Error loading riders:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - CREATE RIDER
========================================================= */

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

      const cleanJobId = clean(jobId).toUpperCase();
      const cleanName = clean(name);
      const cleanPhone = clean(phone);
      const cleanWhatsapp = clean(whatsapp);
      const cleanNationalId = clean(nationalId);
      const cleanBikeType = clean(bikeType);
      const cleanBikeModel = clean(bikeModel);

      if (!cleanJobId || !cleanName || !password) {
        return res.status(400).json({
          error: "Name, Rider Job ID and password are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error: "Rider password must contain at least 6 characters."
        });
      }

      /*
        Check whether Job ID already exists.
      */

      const existing = await db
        .collection("riders")
        .where("jobId", "==", cleanJobId)
        .limit(1)
        .get();

      if (!existing.empty) {
        return res.status(409).json({
          error: "This Rider Job ID is already registered."
        });
      }

      /*
        Internal Firebase email.
      */

      const riderEmail =
        cleanJobId.toLowerCase() +
        "@riders.amirchapchap.local";

      let userRecord;

      try {
        userRecord = await admin.auth().createUser({
          email: riderEmail,
          password: password,
          displayName: cleanName,
          disabled: status === "inactive"
        });
      } catch (error) {
        console.error(
          "Firebase rider account creation error:",
          error.message
        );

        return res.status(500).json({
          error: error.message
        });
      }

      /*
        Give rider role.
      */

      await admin.auth().setCustomUserClaims(
        userRecord.uid,
        {
          role: "rider"
        }
      );

      /*
        Save rider profile.
      */

      await db
        .collection("riders")
        .doc(userRecord.uid)
        .set({
          uid: userRecord.uid,
          jobId: cleanJobId,
          name: cleanName,
          phone: cleanPhone,
          whatsapp: cleanWhatsapp,
          nationalId: cleanNationalId,
          bikeType: cleanBikeType,
          bikeModel: cleanBikeModel,
          email: riderEmail,
          role: "rider",
          status: status === "inactive"
            ? "inactive"
            : "active",
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      /*
        Also create/update users collection.
      */

      await db
        .collection("users")
        .doc(userRecord.uid)
        .set({
          uid: userRecord.uid,
          jobId: cleanJobId,
          name: cleanName,
          displayName: cleanName,
          phone: cleanPhone,
          whatsapp: cleanWhatsapp,
          nationalId: cleanNationalId,
          bikeType: cleanBikeType,
          bikeModel: cleanBikeModel,
          email: riderEmail,
          role: "rider",
          status: status === "inactive"
            ? "inactive"
            : "active",
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      return res.status(201).json({
        message: "Rider registered successfully.",
        rider: {
          uid: userRecord.uid,
          jobId: cleanJobId,
          name: cleanName,
          phone: cleanPhone,
          whatsapp: cleanWhatsapp,
          bikeType: cleanBikeType,
          bikeModel: cleanBikeModel,
          status:
            status === "inactive"
              ? "inactive"
              : "active"
        }
      });

    } catch (error) {
      console.error("Error creating rider:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - CHANGE RIDER STATUS
========================================================= */

app.patch(
  "/api/moderator/riders/:uid/status",
  requireModerator,
  async (req, res) => {
    try {
      const uid = clean(req.params.uid);
      const status = clean(req.body.status).toLowerCase();

      if (!uid) {
        return res.status(400).json({
          error: "Rider UID is required."
        });
      }

      if (!["active", "inactive"].includes(status)) {
        return res.status(400).json({
          error: "Status must be active or inactive."
        });
      }

      const disabled = status === "inactive";

      await admin.auth().updateUser(uid, {
        disabled
      });

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
          {
            merge: true
          }
        );

      return res.status(200).json({
        message: "Rider status updated successfully.",
        status
      });

    } catch (error) {
      console.error("Error changing rider status:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - DELETE RIDER
========================================================= */

app.delete(
  "/api/moderator/riders/:uid",
  requireModerator,
  async (req, res) => {
    try {
      const uid = clean(req.params.uid);

      if (!uid) {
        return res.status(400).json({
          error: "Rider UID is required."
        });
      }

      await admin.auth().deleteUser(uid);

      await db
        .collection("riders")
        .doc(uid)
        .delete();

      await db
        .collection("users")
        .doc(uid)
        .delete();

      return res.status(200).json({
        message: "Rider removed successfully."
      });

    } catch (error) {
      console.error("Error removing rider:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - GET CUSTOMERS
========================================================= */

app.get(
  "/api/moderator/customers",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot = await db
        .collection("users")
        .where("role", "==", "customer")
        .get();

      const customers = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      return res.status(200).json({
        customers
      });

    } catch (error) {
      console.error("Error loading customers:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - GET ORDERS
========================================================= */

app.get(
  "/api/moderator/orders",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot = await db
        .collection("orders")
        .orderBy("createdAt", "desc")
        .get();

      const orders = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      return res.status(200).json({
        orders
      });

    } catch (error) {
      console.error("Error loading orders:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   MODERATOR - APPROVE ORDER
========================================================= */

app.patch(
  "/api/moderator/orders/:orderId/approve",
  requireModerator,
  async (req, res) => {
    try {
      const orderId = clean(req.params.orderId);

      if (!orderId) {
        return res.status(400).json({
          error: "Order ID is required."
        });
      }

      const orderRef =
        db.collection("orders").doc(orderId);

      const orderSnapshot =
        await orderRef.get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      const order = orderSnapshot.data();

      if (order.status !== "pending") {
        return res.status(400).json({
          error:
            "Only pending orders can be approved."
        });
      }

      await orderRef.update({
        status: "approved",
        approvedAt:
          admin.firestore.FieldValue.serverTimestamp(),
        approvedBy: req.user.uid
      });

      return res.status(200).json({
        message: "Order approved successfully."
      });

    } catch (error) {
      console.error("Error approving order:", error);

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   CUSTOMER REGISTER
========================================================= */

app.post(
  "/api/customer/register",
  async (req, res) => {
    try {
      const uid = clean(req.body.uid);
      const email = clean(req.body.email);

      if (!uid || !email) {
        return res.status(400).json({
          error: "Customer UID and email are required."
        });
      }

      await db
        .collection("users")
        .doc(uid)
        .set(
          {
            uid,
            email,
            role: "customer",
            points: 0,
            createdAt:
              admin.firestore.FieldValue.serverTimestamp()
          },
          {
            merge: true
          }
        );

      return res.status(200).json({
        message: "Customer registered successfully."
      });

    } catch (error) {
      console.error(
        "Customer registration error:",
        error
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log(
    `Amir Chap Chap Backend LIVE on port ${PORT}`
  );
});
