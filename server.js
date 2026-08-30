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
  console.error(
    "Firebase Admin initialization error:",
    error.message
  );
  process.exit(1);
}

const db = admin.firestore();

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Amir Chap Chap Backend is running.",
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "Amir Chap Chap Backend",
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   TEST RIDER ROUTE
========================================================= */

app.get("/api/test-riders-route", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Rider route is deployed"
  });
});

/* =========================================================
   VERIFY FIREBASE USER
========================================================= */

async function verifyFirebaseUser(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized. Login required."
      });
    }

    const token = authorization.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    req.user = decodedToken;

    next();

  } catch (error) {
    console.error(
      "Token verification error:",
      error.message
    );

    return res.status(401).json({
      error: "Unauthorized. Invalid Firebase token."
    });
  }
}

/* =========================================================
   VERIFY MODERATOR
========================================================= */

async function verifyAdmin(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized. Moderator login required."
      });
    }

    const token = authorization.substring(7);

    const decodedToken =
      await admin.auth().verifyIdToken(token);

    if (decodedToken.admin !== true) {
      return res.status(403).json({
        error: "Moderator privilege required."
      });
    }

    req.user = decodedToken;

    next();

  } catch (error) {
    console.error(
      "Moderator verification error:",
      error.message
    );

    return res.status(401).json({
      error: "Unauthorized. Invalid moderator token."
    });
  }
}

/* =========================================================
   BOOTSTRAP MODERATOR
========================================================= */

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

/* =========================================================
   SET EXISTING USER AS MODERATOR
========================================================= */

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

/* =========================================================
   CREATE RIDER
========================================================= */

app.post(
  "/api/moderator/riders",
  verifyAdmin,
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
        String(jobId)
          .trim()
          .toUpperCase();

      /* Check duplicate rider ID */

      const existing =
        await db
          .collection("riders")
          .where(
            "jobId",
            "==",
            cleanJobId
          )
          .limit(1)
          .get();

      if (!existing.empty) {
        return res.status(409).json({
          error:
            "This Rider Job ID is already registered."
        });
      }

      /* Internal Firebase email */

      const internalEmail =
        cleanJobId.toLowerCase() +
        "@rider.amirchapchap.com";

      let riderUser;

      try {

        riderUser =
          await admin.auth().createUser({
            email: internalEmail,
            password: password,
            displayName: name
          });

      } catch (error) {

        console.error(
          "Rider Auth creation error:",
          error.message
        );

        return res.status(500).json({
          error:
            "Could not create rider login account: " +
            error.message
        });
      }

      const riderUid =
        riderUser.uid;

      const riderStatus =
        status === "inactive"
          ? "inactive"
          : "active";

      const riderData = {
        uid: riderUid,
        jobId: cleanJobId,
        name: name,
        phone: phone || "",
        whatsapp: whatsapp || "",
        nationalId: nationalId || "",
        bikeType: bikeType || "",
        bikeModel: bikeModel || "",
        status: riderStatus,
        createdBy: req.user.uid,
        createdAt:
          admin.firestore.FieldValue.serverTimestamp()
      };

      /* Save rider */

      await db
        .collection("riders")
        .doc(riderUid)
        .set(riderData);

      /* Save rider account */

      await db
        .collection("riderAccounts")
        .doc(riderUid)
        .set({
          uid: riderUid,
          jobId: cleanJobId,
          name: name,
          phone: phone || "",
          whatsapp: whatsapp || "",
          nationalId: nationalId || "",
          bikeType: bikeType || "",
          bikeModel: bikeModel || "",
          status: riderStatus,
          loginEmail: internalEmail,
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      return res.status(201).json({
        message:
          "Rider registered successfully.",
        rider: {
          uid: riderUid,
          jobId: cleanJobId,
          name: name,
          status: riderStatus
        }
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

/* =========================================================
   GET RIDERS
========================================================= */

app.get(
  "/api/moderator/riders",
  verifyAdmin,
  async (req, res) => {

    try {

      const snapshot =
        await db
          .collection("riders")
          .get();

      const riders =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      return res.status(200).json({
        riders
      });

    } catch (error) {

      console.error(
        "Load riders error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   RIDER LOGIN
========================================================= */

app.post(
  "/api/rider-login",
  async (req, res) => {

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
        String(jobId)
          .trim()
          .toUpperCase();

      const snapshot =
        await db
          .collection("riders")
          .where(
            "jobId",
            "==",
            cleanJobId
          )
          .limit(1)
          .get();

      if (snapshot.empty) {
        return res.status(404).json({
          error:
            "Rider ID not found. Contact the Moderator."
        });
      }

      const rider =
        snapshot.docs[0].data();

      if (rider.status !== "active") {
        return res.status(403).json({
          error:
            "This rider account is inactive. Contact the Moderator."
        });
      }

      const apiKey =
        process.env.FIREBASE_WEB_API_KEY;

      if (!apiKey) {
        return res.status(500).json({
          error:
            "FIREBASE_WEB_API_KEY is missing on the server."
        });
      }

      const internalEmail =
        rider.jobId.toLowerCase() +
        "@rider.amirchapchap.com";

      const authResponse =
        await fetch(
          "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" +
          encodeURIComponent(apiKey),
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify({
                email: internalEmail,
                password: password,
                returnSecureToken: true
              })
          }
        );

      const authData =
        await authResponse.json();

      if (!authResponse.ok) {

        console.error(
          "Rider Firebase login error:",
          authData
        );

        return res.status(401).json({
          error:
            "Invalid Rider Job ID or password."
        });
      }

      return res.status(200).json({

        message:
          "Rider login successful.",

        idToken:
          authData.idToken,

        refreshToken:
          authData.refreshToken,

        rider: {
          uid: rider.uid,
          jobId: rider.jobId,
          name: rider.name,
          phone: rider.phone,
          whatsapp: rider.whatsapp,
          bikeType: rider.bikeType,
          bikeModel: rider.bikeModel,
          status: rider.status
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

/* =========================================================
   UPDATE RIDER STATUS
========================================================= */

app.patch(
  "/api/moderator/riders/:uid/status",
  verifyAdmin,
  async (req, res) => {

    try {

      const { status } =
        req.body;

      if (
        status !== "active" &&
        status !== "inactive"
      ) {
        return res.status(400).json({
          error:
            "Status must be active or inactive."
        });
      }

      const uid =
        req.params.uid;

      await db
        .collection("riders")
        .doc(uid)
        .update({
          status
        });

      await db
        .collection("riderAccounts")
        .doc(uid)
        .update({
          status
        });

      return res.status(200).json({
        message:
          "Rider status updated successfully."
      });

    } catch (error) {

      console.error(
        "Update rider status error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   DELETE RIDER
========================================================= */

app.delete(
  "/api/moderator/riders/:uid",
  verifyAdmin,
  async (req, res) => {

    try {

      const uid =
        req.params.uid;

      await db
        .collection("riders")
        .doc(uid)
        .delete();

      await db
        .collection("riderAccounts")
        .doc(uid)
        .delete();

      try {

        await admin
          .auth()
          .deleteUser(uid);

      } catch (authError) {

        console.error(
          "Firebase Auth rider deletion:",
          authError.message
        );
      }

      return res.status(200).json({
        message:
          "Rider removed successfully."
      });

    } catch (error) {

      console.error(
        "Delete rider error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ALL CUSTOMERS
========================================================= */

app.get(
  "/api/moderator/customers",
  verifyAdmin,
  async (req, res) => {

    try {

      const snapshot =
        await db
          .collection("users")
          .get();

      const customers =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      return res.status(200).json({
        customers
      });

    } catch (error) {

      console.error(
        "Load customers error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ALL ORDERS
========================================================= */

app.get(
  "/api/moderator/orders",
  verifyAdmin,
  async (req, res) => {

    try {

      const snapshot =
        await db
          .collection("orders")
          .get();

      const orders =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      return res.status(200).json({
        orders
      });

    } catch (error) {

      console.error(
        "Load orders error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   APPROVE ORDER
========================================================= */

app.patch(
  "/api/moderator/orders/:orderId/approve",
  verifyAdmin,
  async (req, res) => {

    try {

      const orderId =
        req.params.orderId;

      await db
        .collection("orders")
        .doc(orderId)
        .update({
          status: "approved",
          approvedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      return res.status(200).json({
        message:
          "Order approved successfully."
      });

    } catch (error) {

      console.error(
        "Approve order error:",
        error.message
      );

      return res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   404 HANDLER
   THIS MUST BE AFTER ALL ROUTES
========================================================= */

app.use((req, res) => {

  return res.status(404).json({
    error:
      "API endpoint not found.",
    path:
      req.originalUrl
  });

});

/* =========================================================
   SERVER
   ONLY ONE app.listen()
========================================================= */

app.listen(PORT, () => {

  console.log(
  `Amir Chap Chap Backend LIVE on port ${PORT}`
);

});
