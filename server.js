const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

/* =========================
   FIREBASE ADMIN
========================= */

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
  console.error(
    "FIREBASE_SERVICE_ACCOUNT is not valid JSON."
  );
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

console.log("Firebase Admin initialized successfully.");


/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
  res.status(200).send(
    "Amir Chap Chap Backend is running."
  );
});


/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "Amir Chap Chap Backend"
  });
});


/* =========================
   ADMIN VERIFICATION
========================= */

const verifyAdmin = async (req, res, next) => {

  try {

    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {

      return res.status(401).json({
        error:
          "Unauthorized: No valid token provided."
      });

    }

    const token =
      authorization.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    if (decodedToken.admin !== true) {

      return res.status(403).json({
        error:
          "Forbidden: Moderator privilege required."
      });

    }

    req.user = decodedToken;

    next();

  } catch (error) {

    console.error(
      "Admin verification error:",
      error.message
    );

    return res.status(401).json({
      error:
        "Unauthorized: Invalid token."
    });

  }

};


/* =========================
   BOOTSTRAP MODERATOR
========================= */

app.post(
  "/api/bootstrap-admin",
  async (req, res) => {

    try {

      const secret =
        req.headers["x-bootstrap-secret"];

      if (
        !secret ||
        !process.env.BOOTSTRAP_SECRET ||
        secret !== process.env.BOOTSTRAP_SECRET
      ) {

        return res.status(403).json({
          error:
            "Invalid bootstrap secret."
        });

      }

      const {
        email,
        password,
        displayName
      } = req.body;

      if (!email || !password) {

        return res.status(400).json({
          error:
            "Email and password are required."
        });

      }

      let userRecord;

      try {

        userRecord =
          await admin.auth()
            .getUserByEmail(email);

      } catch (error) {

        if (
          error.code ===
          "auth/user-not-found"
        ) {

          userRecord =
            await admin.auth()
              .createUser({

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

      await admin.auth()
        .setCustomUserClaims(
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

            uid:
              userRecord.uid,

            email:
              userRecord.email || email,

            role:
              "admin",

            displayName:
              displayName ||
              userRecord.displayName ||
              "Amir Chap Chap Moderator",

            updatedAt:
              admin.firestore.FieldValue
                .serverTimestamp()

          },
          {
            merge: true
          }
        );

      return res.status(200).json({

        message:
          "Moderator account is ready.",

        uid:
          userRecord.uid,

        email:
          userRecord.email || email

      });

    } catch (error) {

      console.error(
        "Bootstrap moderator error:",
        error.message
      );

      return res.status(500).json({
        error:
          error.message
      });

    }

  }
);


/* =========================
   SET EXISTING USER AS MODERATOR
========================= */

app.post(
  "/api/set-moderator",
  async (req, res) => {

    try {

      const setupSecret =
        req.headers["x-setup-secret"];

      if (
        !setupSecret ||
        setupSecret !==
        process.env.BOOTSTRAP_SECRET
      ) {

        return res.status(403).json({
          error:
            "Invalid setup secret."
        });

      }

      const { uid } =
        req.body;

      if (!uid) {

        return res.status(400).json({
          error:
            "Firebase UID is required."
        });

      }

      const userRecord =
        await admin.auth()
          .getUser(uid);

      await admin.auth()
        .setCustomUserClaims(
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

            email:
              userRecord.email || "",

            role:
              "admin",

            displayName:
              userRecord.displayName ||
              "Amir Chap Chap Moderator",

            updatedAt:
              admin.firestore.FieldValue
                .serverTimestamp()

          },
          {
            merge: true
          }
        );

      return res.status(200).json({

        message:
          "Moderator role assigned successfully.",

        uid

      });

    } catch (error) {

      console.error(
        "Set moderator error:",
        error.message
      );

      return res.status(500).json({
        error:
          error.message
      });

    }

  }
);


/* ==========================================================
   CREATE RIDER
========================================================== */

app.post(
  "/api/create-rider",
  verifyAdmin,
  async (req, res) => {

    try {

      const {
        name,
        phone,
        whatsapp,
        nationalId,
        bikeType,
        bikeModel,
        jobId,
        email,
        password,
        status
      } = req.body;


      /* -------------------------
         VALIDATION
      ------------------------- */

      if (
        !name ||
        !jobId ||
        !email ||
        !password
      ) {

        return res.status(400).json({

          error:
            "Name, Rider ID, email and password are required."

        });

      }


      /* -------------------------
         CHECK RIDER ID
      ------------------------- */

      const
