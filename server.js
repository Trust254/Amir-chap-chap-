const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const crypto = require("crypto");

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
   VERIFY MODERATOR
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
      error: "Unauthorized: Invalid token."
    });

  }

};


/* =========================
   BOOTSTRAP MODERATOR
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
        error:
          "Email and password are required."
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
          email:
            userRecord.email || email,
          role: "admin",
          displayName:
            displayName ||
            userRecord.displayName ||
            "Amir Chap Chap Moderator",
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
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
      error: error.message
    });

  }

});


/* =========================
   SET EXISTING USER MODERATOR
========================= */

app.post("/api/set-moderator", async (req, res) => {

  try {

    const setupSecret =
      req.headers["x-setup-secret"];

    if (
      !setupSecret ||
      setupSecret !==
        process.env.BOOTSTRAP_SECRET
    ) {

      return res.status(403).json({
        error: "Invalid setup secret."
      });

    }

    const { uid } = req.body;

    if (!uid) {

      return res.status(400).json({
        error:
          "Firebase UID is required."
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
          email:
            userRecord.email || "",
          role: "admin",
          displayName:
            userRecord.displayName ||
            "Amir Chap Chap Moderator",
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
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
      error: error.message
    });

  }

});


/* =========================
   MODERATOR CREATE RIDER
========================= */

app.post(
  "/api/riders",
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
        status
      } = req.body;

      if (!name || !jobId) {

        return res.status(400).json({
          error:
            "Rider name and Rider Code are required."
        });

      }

      const riderCode =
        String(jobId)
          .trim()
          .toUpperCase();

      const existing =
        await db
          .collection("riders")
          .where(
            "jobId",
            "==",
            riderCode
          )
          .limit(1)
          .get();

      if (!existing.empty) {

        return res.status(409).json({
          error:
            "This Rider Code is already registered."
        });

      }

      const riderRef =
        db.collection("riders").doc();

      const riderUid =
        riderRef.id;

      const riderData = {

        uid: riderUid,

        jobId: riderCode,

        name: String(name).trim(),

        phone:
          String(phone || "").trim(),

        whatsapp:
          String(whatsapp || "").trim(),

        nationalId:
          String(nationalId || "").trim(),

        bikeType:
          String(bikeType || "").trim(),

        bikeModel:
          String(bikeModel || "").trim(),

        status:
          status === "inactive"
            ? "inactive"
            : "active",

        createdAt:
          admin.firestore.FieldValue.serverTimestamp(),

        createdBy:
          req.user.uid

      };

      await riderRef.set(riderData);

      await db
        .collection("riderAccounts")
        .doc(riderUid)
        .set(riderData);

      return res.status(201).json({

        message:
          "Rider registered successfully.",

        riderCode,

        riderUid

      });

    } catch (error) {

      console.error(
        "Create rider error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });

    }

  }
);


/* =========================
   RIDER CODE LOGIN
========================= */

app.post(
  "/api/rider-login",
  async (req, res) => {

    try {

      const code =
        String(
          req.body.code || ""
        )
          .trim()
          .toUpperCase();

      if (!code) {

        return res.status(400).json({
          error:
            "Rider Code is required."
        });

      }

      const snapshot =
        await db
          .collection("riders")
          .where(
            "jobId",
            "==",
            code
          )
          .limit(1)
          .get();

      if (snapshot.empty) {

        return res.status(401).json({
          error:
            "Invalid Rider Code."
        });

      }

      const riderDoc =
        snapshot.docs[0];

      const rider =
        riderDoc.data();

      if (rider.status !== "active") {

        return res.status(403).json({
          error:
            "This rider account is inactive. Contact the Moderator."
        });

      }

      /*
       Temporary session token.

       The frontend will send this token
       when requesting rider information.
      */

      const sessionToken =
        crypto.randomBytes(32).toString("hex");

      await db
        .collection("riderSessions")
        .doc(sessionToken)
        .set({

          riderUid:
            rider.uid || riderDoc.id,

          riderCode:
            rider.jobId,

          createdAt:
            admin.firestore.FieldValue.serverTimestamp(),

          expiresAt:
            new Date(
              Date.now() +
              24 * 60 * 60 * 1000
            )

        });

      return res.status(200).json({

        message:
          "Rider login successful.",

        token:
          sessionToken,

        rider: {

          uid:
            rider.uid || riderDoc.id,

          jobId:
            rider.jobId || "",

          name:
            rider.name || "",

          phone:
            rider.phone || "",

          whatsapp:
            rider.whatsapp || "",

          bikeType:
            rider.bikeType || "",

          bikeModel:
            rider.bikeModel || "",

          status:
            rider.status || "active"

        }

      });

    } catch (error) {

      console.error(
        "Rider login error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });

    }

  }
);


/* =========================
   VERIFY RIDER SESSION
========================= */

const verifyRider = async (
  req,
  res,
  next
) => {

  try {

    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {

      return res.status(401).json({
        error:
          "Rider session required."
      });

    }

    const token =
      authorization.substring(7);

    const session =
      await db
        .collection("riderSessions")
        .doc(token)
        .get();

    if (!session.exists) {

      return res.status(401).json({
        error:
          "Invalid rider session."
      });

    }

    const data =
      session.data();

    const expiresAt =
      data.expiresAt;

    if (
      expiresAt &&
      expiresAt.toDate &&
      expiresAt.toDate() < new Date()
    ) {

      await session.ref.delete();

      return res.status(401).json({
        error:
          "Rider session expired."
      });

    }

    req.rider = data;

    next();

  } catch (error) {

    console.error(
      "Rider verification error:",
      error.message
    );

    return res.status(401).json({
      error:
        "Invalid rider session."
    });

  }

};


/* =========================
   RIDER PROFILE
========================= */

app.get(
  "/api/rider/me",
  verifyRider,
  async (req, res) => {

    try {

      const riderSnap =
        await db
          .collection("riders")
          .doc(req.rider.riderUid)
          .get();

      if (!riderSnap.exists) {

        return res.status(404).json({
          error:
            "Rider record not found."
        });

      }

      return res.status(200).json(
        riderSnap.data()
      );

    } catch (error) {

      return res.status(500).json({
        error: error.message
      });

    }

  }
);


/* =========================
   RIDER LOGOUT
========================= */

app.post(
  "/api/rider-logout",
  verifyRider,
  async (req, res) => {

    try {

      const authorization =
        req.headers.authorization || "";

      const token =
        authorization.substring(7);

      await db
        .collection("riderSessions")
        .doc(token)
        .delete();

      return res.status(200).json({
        message:
          "Rider logged out successfully."
      });

    } catch (error) {

      return res.status(500).json({
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
