const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 10000;

/* =========================
   MIDDLEWARE
========================= */

app.use(cors());
app.use(express.json());

/* =========================
   FIREBASE ADMIN
========================= */

const privateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
  : undefined;

if (
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  privateKey
) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: privateKey
    })
  });

  console.log("Firebase Admin initialized successfully.");
} else {
  console.warn(
    "Firebase environment variables are missing or incomplete."
  );
}

const db = admin.firestore();

/* =========================
   ROOT ROUTE
========================= */

app.get("/", (req, res) => {
  res.status(200).send(
    "Amir Chap Chap Backend is running."
  );
});

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "Amir Chap Chap Backend",
    timestamp: new Date().toISOString()
  });
});

/* =========================
   VERIFY ADMIN
========================= */

const verifyAdmin = async (req, res, next) => {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized: No valid token provided."
      });
    }

    const token = authorization.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    if (decodedToken.admin !== true) {
      return res.status(403).json({
        error: "Forbidden: Moderator privilege required."
      });
    }

    req.user = decodedToken;
    next();

  } catch (error) {
    console.error("Admin verification error:", error);

    return res.status(401).json({
      error: "Unauthorized: Invalid token."
    });
  }
};

/* =========================
   BOOTSTRAP FIRST MODERATOR
   =========================
   One-time setup endpoint.
========================= */

app.post("/api/bootstrap-admin", async (req, res) => {

  try {

    const secret =
      req.headers["x-bootstrap-secret"];

    if (
      !secret ||
      !process.env.BOOTSTRAP_SECRET ||
      secret !== process.env.BOOTSTRAP_SECRET
    ) {
      return res.status(403).json({
        error: "Invalid bootstrap secret."
      });
    }

    const {
      email,
      password,
      displayName
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    let userRecord;

    try {

      userRecord =
        await admin.auth().getUserByEmail(email);

    } catch (error) {

      if (error.code === "auth/user-not-found") {

        userRecord =
          await admin.auth().createUser({
            email,
            password,
            displayName:
              displayName ||
              "Amir Chap Chap Moderator"
          });

      } else {
        throw error;
      }
    }

    await admin.auth().setCustomUserClaims(
      userRecord.uid,
      {
        admin: true
      }
    );

    await db
      .collection("users")
      .doc(userRecord.uid)
      .set(
        {
          uid: userRecord.uid,
          email: userRecord.email,
          role: "admin",
          displayName:
            displayName ||
            userRecord.displayName ||
            "Amir Chap Chap Moderator",
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    return res.status(200).json({
      message:
        "Moderator account is ready.",
      uid: userRecord.uid,
      email: userRecord.email
    });

  } catch (error) {

    console.error(
      "Bootstrap moderator error:",
      error
    );

    return res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   SET EXISTING USER AS MODERATOR
========================= */

app.post("/api/set-moderator", async (req, res) => {

  try {

    const setupSecret =
      req.headers["x-setup-secret"];

    if (
      !setupSecret ||
      setupSecret !== process.env.BOOTSTRAP_SECRET
    ) {
      return res.status(403).json({
        error: "Invalid setup secret."
      });
    }

    const { uid } = req.body;

    if (!uid) {
      return res.status(400).json({
        error: "Firebase UID is required."
      });
    }

    const userRecord =
      await admin.auth().getUser(uid);

    await admin.auth().setCustomUserClaims(
      uid,
      {
        admin: true
      }
    );

    await db
      .collection("users")
      .doc(uid)
      .set(
        {
          uid,
          email: userRecord.email || "",
          role: "admin",
          displayName:
            userRecord.displayName ||
            "Amir Chap Chap Moderator",
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    return res.status(200).json({
      message:
        "Moderator role assigned successfully.",
      uid: uid
    });

  } catch (error) {

    console.error(
      "Set moderator error:",
      error
    );

    return res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   CREATE RIDER
========================= */

app.post(
  "/api/create-rider",
  verifyAdmin,
  async (req, res) => {

    try {

      const {
        name,
        phone,
        email,
        password,
        motorbikeType,
        motorbikeModel
      } = req.body;

      if (
        !name ||
        !phone ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, phone, email and password are required."
        });
      }

      const userRecord =
        await admin.auth().createUser({
          email,
          password,
          displayName: name
        });

      const counterRef =
        db.collection("counters")
          .doc("riders");

      const riderId =
        await db.runTransaction(
          async (transaction) => {

            const counterDoc =
              await transaction.get(
                counterRef
              );

            let count = 1;

            if (counterDoc.exists) {
              count =
                Number(
                  counterDoc.data().count || 0
                ) + 1;
            }

            transaction.set(
              counterRef,
              { count },
              { merge: true }
            );

            return `RIDER-${String(count)
              .padStart(4, "0")}`;
          }
        );

      await db
        .collection("riders")
        .doc(userRecord.uid)
        .set({
          uid: userRecord.uid,
          riderId,
          name,
          phone,
          email,
          motorbikeType:
            motorbikeType || "N/A",
          motorbikeModel:
            motorbikeModel || "N/A",
          status: "active",
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      return res.status(201).json({
        message:
          "Rider account created successfully.",
        uid: userRecord.uid,
        riderId
      });

    } catch (error) {

      console.error(
        "Create rider error:",
        error
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================
   DISABLE RIDER
========================= */

app.post(
  "/api/disable-rider",
  verifyAdmin,
  async (req, res) => {

    try {

      const { uid } = req.body;

      if (!uid) {
        return res.status(400).json({
          error: "Rider UID is required."
        });
      }

      await admin.auth().updateUser(
        uid,
        {
          disabled: true
        }
      );

      await db
        .collection("riders")
        .doc(uid)
        .set(
          {
            status: "disabled"
          },
          { merge: true }
        );

      res.json({
        message: "Rider disabled successfully."
      });

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================
   ENABLE RIDER
========================= */

app.post(
  "/api/enable-rider",
  verifyAdmin,
  async (req, res) => {

    try {

      const { uid } = req.body;

      if (!uid) {
        return res.status(400).json({
          error: "Rider UID is required."
        });
      }

      await admin.auth().updateUser(
        uid,
        {
          disabled: false
        }
      );

      await db
        .collection("riders")
        .doc(uid)
        .set(
          {
            status: "active"
          },
          { merge: true }
        );

      res.json({
        message: "Rider enabled successfully."
      });

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================
   DELETE RIDER
========================= */

app.post(
  "/api/delete-rider",
  verifyAdmin,
  async (req, res) => {

    try {

      const { uid } = req.body;

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

      res.json({
        message: "Rider deleted successfully."
      });

    } catch (error) {

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================
   SERVER
========================= */

app.listen(PORT, () => {

  console.log(
    `Server listening on port ${PORT}`
  );

});
