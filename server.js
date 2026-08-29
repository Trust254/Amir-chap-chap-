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
      privateKey
    })
  });

  console.log("Firebase Admin initialized successfully.");
} else {
  console.warn("Firebase environment variables are missing.");
}

const db = admin.firestore();
const auth = admin.auth();

/* =========================
   ROOT / HEALTH
========================= */

app.get("/", (req, res) => {
  res.status(200).send("Amir Chap Chap Backend is running.");
});

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "Amir Chap Chap Backend",
    time: new Date().toISOString()
  });
});

/* =========================
   VERIFY MODERATOR
========================= */

async function verifyAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authorization token required."
      });
    }

    const token = header.substring(7);

    const decoded = await auth.verifyIdToken(token);

    if (decoded.admin !== true) {
      return res.status(403).json({
        error: "Moderator permission required."
      });
    }

    req.user = decoded;
    next();

  } catch (error) {
    console.error("Admin verification error:", error);

    return res.status(401).json({
      error: "Invalid or expired Firebase login."
    });
  }
}

/* =========================
   BOOTSTRAP FIRST MODERATOR
========================= */

app.post("/api/bootstrap-admin", async (req, res) => {

  try {

    const secret = req.headers["x-bootstrap-secret"];

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

      userRecord = await auth.getUserByEmail(email);

    } catch (error) {

      userRecord = await auth.createUser({
        email,
        password,
        displayName: displayName || "Amir Chap Chap Moderator"
      });

    }

    await auth.setCustomUserClaims(userRecord.uid, {
      admin: true
    });

    await db
      .collection("users")
      .doc(userRecord.uid)
      .set(
        {
          uid: userRecord.uid,
          email: userRecord.email,
          name:
            displayName ||
            userRecord.displayName ||
            "Moderator",
          role: "admin",
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    res.status(200).json({
      message: "Moderator account is ready.",
      uid: userRecord.uid,
      email: userRecord.email
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   GENERATE RIDER ID
========================= */

async function generateRiderId() {

  const counterRef =
    db.collection("counters").doc("riders");

  return await db.runTransaction(async transaction => {

    const snapshot =
      await transaction.get(counterRef);

    let count = 1;

    if (snapshot.exists) {

      const oldCount =
        Number(snapshot.data().count || 0);

      count = oldCount + 1;
    }

    transaction.set(
      counterRef,
      {
        count
      },
      {
        merge: true
      }
    );

    return `RIDER-${String(count).padStart(4, "0")}`;
  });
}

/* =========================
   CREATE RIDER
========================= */

app.post("/api/createRider", verifyAdmin, async (req, res) => {

  try {

    const {
      name,
      phone,
      email,
      password,
      motorbikeType,
      motorbikeModel
    } = req.body;

    if (!name || !phone || !email || !password) {

      return res.status(400).json({
        error:
          "Name, phone, email and password are required."
      });
    }

    const riderId =
      await generateRiderId();

    const userRecord =
      await auth.createUser({
        email,
        password,
        displayName: name
      });

    const riderData = {

      uid: userRecord.uid,

      riderId,

      name,

      phone,

      email,

      motorbikeType:
        motorbikeType || "Not specified",

      motorbikeModel:
        motorbikeModel || "Not specified",

      status: "active",

      role: "rider",

      createdAt:
        admin.firestore.FieldValue.serverTimestamp(),

      createdBy:
        req.user.uid
    };

    await db
      .collection("riders")
      .doc(userRecord.uid)
      .set(riderData);

    res.status(201).json({

      message:
        "Rider account created successfully.",

      riderId,

      uid: userRecord.uid,

      rider: riderData
    });

  } catch (error) {

    console.error("Create rider error:", error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   LIST RIDERS
========================= */

app.get("/api/riders", verifyAdmin, async (req, res) => {

  try {

    const snapshot =
      await db.collection("riders").get();

    const riders =
      snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

    res.json({
      riders
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   DISABLE RIDER
========================= */

app.post("/api/disableRider", verifyAdmin, async (req, res) => {

  try {

    const { uid } = req.body;

    if (!uid) {

      return res.status(400).json({
        error: "Rider UID is required."
      });
    }

    await auth.updateUser(uid, {
      disabled: true
    });

    await db
      .collection("riders")
      .doc(uid)
      .update({
        status: "inactive",
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({
      message: "Rider account disabled."
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   ENABLE RIDER
========================= */

app.post("/api/enableRider", verifyAdmin, async (req, res) => {

  try {

    const { uid } = req.body;

    if (!uid) {

      return res.status(400).json({
        error: "Rider UID is required."
      });
    }

    await auth.updateUser(uid, {
      disabled: false
    });

    await db
      .collection("riders")
      .doc(uid)
      .update({
        status: "active",
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({
      message: "Rider account activated."
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   DELETE RIDER
========================= */

app.post("/api/deleteRider", verifyAdmin, async (req, res) => {

  try {

    const { uid } = req.body;

    if (!uid) {

      return res.status(400).json({
        error: "Rider UID is required."
      });
    }

    await auth.deleteUser(uid);

    await db
      .collection("riders")
      .doc(uid)
      .delete();

    res.json({
      message:
        "Rider account and rider record deleted."
    });

  } catch (error) {

    console.error("Delete rider error:", error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================
   SERVER
========================= */

app.listen(PORT, () => {

  console.log(
    `Server listening on port ${PORT}`
  );

});
