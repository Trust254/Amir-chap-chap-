const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

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
   HELPERS
========================================== */

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
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
   AUTHENTICATION
========================================== */

async function verifyFirebaseToken(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication token required."
      });
    }

    const token = header.substring(7);

    req.user =
      await admin.auth().verifyIdToken(token);

    next();

  } catch (error) {
    console.error(
      "Token verification failed:",
      error.message
    );

    return res.status(401).json({
      error: "Invalid or expired authentication token."
    });
  }
}

async function requireModerator(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Moderator authentication required."
      });
    }

    const token = header.substring(7);

    const decoded =
      await admin.auth().verifyIdToken(token);

    if (decoded.admin !== true) {
      return res.status(403).json({
        error: "Moderator authorization required."
      });
    }

    req.user = decoded;

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
   HOME / HEALTH
========================================== */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    message:
      "Amir Chap Chap Backend is running smoothly.",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "online",
    service: "Amir Chap Chap Backend",
    timestamp: new Date().toISOString()
  });
});

app.get(
  "/api/moderator/riders/test",
  (req, res) => {
    res.status(200).json({
      status: "OK",
      message: "Rider route is deployed"
    });
  }
);

/* ==========================================
   CUSTOMER REGISTER
========================================== */

app.post(
  "/api/customer/register",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const email =
        req.body.email ||
        req.user.email ||
        "";

      await db
        .collection("users")
        .doc(uid)
        .set(
          {
            uid,
            email,
            role: "customer",
            points: 0,
            updatedAt:
              admin.firestore.FieldValue.serverTimestamp()
          },
          { merge: true }
        );

      res.json({
        message:
          "Customer registered successfully."
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
        String(jobId)
          .trim()
          .toUpperCase();

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
            "This Rider Job ID already exists."
        });
      }

      const internalEmail =
        `${cleanJobId.toLowerCase()}@rider.amirchapchap.local`;

      const userRecord =
        await admin.auth().createUser({
          email: internalEmail,
          password:
            crypto.randomBytes(32).toString("hex"),
          displayName: name
        });

      await admin
        .auth()
        .setCustomUserClaims(
          userRecord.uid,
          {
            role: "rider",
            jobId: cleanJobId
          }
        );

      const rider = {
        uid: userRecord.uid,
        jobId: cleanJobId,
        name: String(name).trim(),
        phone: phone || "",
        whatsapp: whatsapp || "",
        nationalId: nationalId || "",
        bikeType: bikeType || "",
        bikeModel: bikeModel || "",
        passwordHash:
          hashPassword(password),
        status: status || "active",
        role: "rider",
        createdAt:
          admin.firestore.FieldValue.serverTimestamp()
      };

      await db
        .collection("riders")
        .doc(userRecord.uid)
        .set(rider);

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
        message:
          "Rider registered successfully.",
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
        return res.status(401).json({
          error:
            "Invalid Rider Job ID or password."
        });
      }

      const rider =
        snapshot.docs[0].data();

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
          error:
            "Invalid Rider Job ID or password."
        });
      }

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

      res.json({
        message:
          "Rider login successful.",
        token: customToken,
        rider: {
          uid: rider.uid,
          jobId: rider.jobId,
          name: rider.name,
          phone: rider.phone || "",
          whatsapp: rider.whatsapp || "",
          bikeType:
            rider.bikeType || "",
          bikeModel:
            rider.bikeModel || "",
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
  }
);

/* ==========================================
   GET RIDERS
========================================== */

app.get(
  "/api/moderator/riders",
  requireModerator,
  async (req, res) => {
    try {
      const snapshot =
        await db
          .collection("riders")
          .orderBy(
            "createdAt",
            "desc"
          )
          .get();

      const riders =
        snapshot.docs.map(doc => {
          const data = doc.data();

          delete data.passwordHash;

          return {
            id: doc.id,
            ...data
          };
        });

      res.json({
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
   RIDER STATUS
========================================== */

app.patch(
  "/api/moderator/riders/:uid/status",
  requireModerator,
  async (req, res) => {
    try {
      const uid =
        req.params.uid;

      const {
        status
      } = req.body;

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
        .set(
          {
            status
          },
          { merge: true }
        );

      await db
        .collection("users")
        .doc(uid)
        .set(
          {
            status
          },
          { merge: true }
        );

      await admin
        .auth()
        .updateUser(
          uid,
          {
            disabled:
              status !== "active"
          }
        );

      res.json({
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
      const uid =
        req.params.uid;

      await admin
        .auth()
        .deleteUser(uid);

      await db
        .collection("riders")
        .doc(uid)
        .delete();

      await db
        .collection("users")
        .doc(uid)
        .delete();

      res.json({
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
          .where(
            "role",
            "==",
            "customer"
          )
          .get();

      const customers =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.json({
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
          .orderBy(
            "createdAt",
            "desc"
          )
          .get();

      const orders =
        snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      res.json({
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
        db
          .collection("orders")
          .doc(orderId);

      const orderSnapshot =
        await orderRef.get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      const order =
        orderSnapshot.data();

      if (
        order.status !== "pending"
      ) {
        return res.status(400).json({
          error:
            `Order is already ${order.status}.`
        });
      }

      await orderRef.update({
        status: "approved",
        approvedAt:
          admin.firestore.FieldValue.serverTimestamp(),
        approvedBy:
          req.user.uid
      });

      res.json({
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
   ASSIGN RIDER
========================================== */

app.patch(
  "/api/moderator/orders/:orderId/assign-rider",
  requireModerator,
  async (req, res) => {
    try {
      const orderId =
        req.params.orderId;

      const {
        riderUid
      } = req.body;

      if (!riderUid) {
        return res.status(400).json({
          error:
            "Rider UID is required."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(orderId);

      const riderRef =
        db
          .collection("riders")
          .doc(riderUid);

      const [
        orderSnapshot,
        riderSnapshot
      ] = await Promise.all([
        orderRef.get(),
        riderRef.get()
      ]);

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      if (!riderSnapshot.exists) {
        return res.status(404).json({
          error: "Rider not found."
        });
      }

      const order =
        orderSnapshot.data();

      const rider =
        riderSnapshot.data();

      if (rider.status !== "active") {
        return res.status(400).json({
          error:
            "Selected rider is not active."
        });
      }

      if (
        order.status !== "approved" &&
        order.status !== "assigned"
      ) {
        return res.status(400).json({
          error:
            "Only approved orders can be assigned."
        });
      }

      await orderRef.update({
        status: "assigned",

        riderUid:
          rider.uid,

        riderName:
          rider.name || "",

        riderPhone:
          rider.phone || "",

        riderWhatsapp:
          rider.whatsapp || "",

        riderJobId:
          rider.jobId || "",

        assignedAt:
          admin.firestore.FieldValue.serverTimestamp(),

        assignedBy:
          req.user.uid
      });

      await db
        .collection("notifications")
        .add({
          riderUid:
            rider.uid,

          orderId,

          title:
            "New Delivery Job",

          message:
            `New job: ${order.pickup || ""} → ${order.destination || ""}. Fare KSh ${Number(order.fare || 0).toLocaleString()}.`,

          read: false,

          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      res.json({
        message:
          "Rider assigned successfully.",
        rider: {
          uid: rider.uid,
          name: rider.name,
          jobId: rider.jobId
        }
      });

    } catch (error) {
      console.error(
        "ASSIGN RIDER ERROR:",
        error
      );

      res.status(500).json({
        error:
          error.message ||
          "Could not assign rider."
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
      if (
        req.user.role !== "rider"
      ) {
        return res.status(403).json({
          error:
            "Rider access required."
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

      res.json({
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
      if (
        req.user.role !== "rider"
      ) {
        return res.status(403).json({
          error:
            "Rider access required."
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

      res.json({
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
   RIDER MARK PICKED UP
========================================== */

app.patch(
  "/api/rider/orders/:orderId/picked-up",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      if (
        req.user.role !== "rider"
      ) {
        return res.status(403).json({
          error:
            "Rider access required."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(req.params.orderId);

      const snapshot =
        await orderRef.get();

      if (!snapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      const order =
        snapshot.data();

      if (
        order.riderUid !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            "This job is not assigned to you."
        });
      }

      await orderRef.update({
        status: "picked_up",

        pickedUpAt:
          admin.firestore.FieldValue.serverTimestamp()
      });

      res.json({
        message:
          "Order marked as picked up."
      });

    } catch (error) {
      console.error(
        "Picked up error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   RIDER MARK DELIVERED
   AUTOMATIC POINTS
========================================== */

app.patch(
  "/api/rider/orders/:orderId/delivered",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      if (
        req.user.role !== "rider"
      ) {
        return res.status(403).json({
          error:
            "Rider access required."
        });
      }

      const orderId =
        req.params.orderId;

      const orderRef =
        db
          .collection("orders")
          .doc(orderId);

      const orderSnapshot =
        await orderRef.get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      const order =
        orderSnapshot.data();

      if (
        order.riderUid !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            "This job is not assigned to you."
        });
      }

      if (
        order.status === "delivered"
      ) {
        return res.status(400).json({
          error:
            "This order has already been delivered."
        });
      }

      const customerUid =
        order.userId;

      const pointsEarned =
        Math.max(
          1,
          Math.floor(
            Number(order.fare || 0) / 10
          )
        );

      await db.runTransaction(
        async transaction => {

          const customerRef =
            db
              .collection("users")
              .doc(customerUid);

          const customerSnapshot =
            await transaction.get(
              customerRef
            );

          let currentPoints = 0;

          if (
            customerSnapshot.exists
          ) {
            currentPoints =
              Number(
                customerSnapshot.data()
                  .points || 0
              );
          }

          transaction.update(
            orderRef,
            {
              status:
                "delivered",

              deliveredAt:
                admin.firestore.FieldValue.serverTimestamp(),

              pointsAwarded:
                pointsEarned
            }
          );

          transaction.set(
            customerRef,
            {
              points:
                currentPoints +
                pointsEarned,

              updatedAt:
                admin.firestore.FieldValue.serverTimestamp()
            },
            {
              merge: true
            }
          );

          const pointsRef =
            db
              .collection("pointsTransactions")
              .doc();

          transaction.set(
            pointsRef,
            {
              userId:
                customerUid,

              orderId,

              type:
                "earned",

              points:
                pointsEarned,

              reason:
                "Completed delivery",

              createdAt:
                admin.firestore.FieldValue.serverTimestamp()
            }
          );
        }
      );

      res.json({
        message:
          "Order marked as delivered.",
        pointsEarned
      });

    } catch (error) {
      console.error(
        "Delivery completion error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   CUSTOMER POINTS
========================================== */

app.get(
  "/api/customer/points",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const userRef =
        db
          .collection("users")
          .doc(req.user.uid);

      const snapshot =
        await userRef.get();

      const points =
        snapshot.exists
          ? Number(
              snapshot.data().points || 0
            )
          : 0;

      res.json({
        points
      });

    } catch (error) {
      console.error(
        "Points error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   CUSTOMER PAYMENT / POINTS CHECK
========================================== */

app.post(
  "/api/customer/check-points",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const fare =
        Number(req.body.fare || 0);

      const userRef =
        db
          .collection("users")
          .doc(req.user.uid);

      const snapshot =
        await userRef.get();

      const points =
        snapshot.exists
          ? Number(
              snapshot.data().points || 0
            )
          : 0;

      /*
        1 point = KSh 1 for redemption.
      */

      if (points < fare) {
        return res.status(400).json({
          error:
            "Insufficient points.",
          points,
          required: fare
        });
      }

      res.json({
        allowed: true,
        points,
        required: fare
      });

    } catch (error) {
      console.error(
        "Point check error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   SPEND POINTS
========================================== */

app.post(
  "/api/customer/spend-points",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const {
        orderId,
        points
      } = req.body;

      const amount =
        Number(points || 0);

      if (
        !orderId ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            "Order ID and valid points are required."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(orderId);

      const customerRef =
        db
          .collection("users")
          .doc(req.user.uid);

      await db.runTransaction(
        async transaction => {

          const [
            orderSnapshot,
            customerSnapshot
          ] = await Promise.all([
            transaction.get(orderRef),
            transaction.get(customerRef)
          ]);

          if (
            !orderSnapshot.exists
          ) {
            throw new Error(
              "Order not found."
            );
          }

          if (
            orderSnapshot.data()
              .userId !==
            req.user.uid
          ) {
            throw new Error(
              "This order does not belong to you."
            );
          }

          const currentPoints =
            customerSnapshot.exists
              ? Number(
                  customerSnapshot.data()
                    .points || 0
                )
              : 0;

          if (
            currentPoints < amount
          ) {
            throw new Error(
              "Insufficient points."
            );
          }

          transaction.update(
            customerRef,
            {
              points:
                currentPoints -
                amount
            }
          );

          transaction.update(
            orderRef,
            {
              pointsUsed:
                amount,

              paymentMethod:
                "points",

              paymentStatus:
                "paid"
            }
          );

          const pointsRef =
            db
              .collection(
                "pointsTransactions"
              )
              .doc();

          transaction.set(
            pointsRef,
            {
              userId:
                req.user.uid,

              orderId,

              type:
                "spent",

              points:
                amount,

              reason:
                "Paid for service",

              createdAt:
                admin.firestore.FieldValue.serverTimestamp()
            }
          );
        }
      );

      res.json({
        message:
          "Points payment successful."
      });

    } catch (error) {
      console.error(
        "Spend points error:",
        error
      );

      res.status(400).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   M-PESA PAYMENT RECORD
========================================== */

app.post(
  "/api/customer/mpesa-payment",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const {
        orderId,
        amount,
        mpesaReference
      } = req.body;

      if (
        !orderId ||
        !amount
      ) {
        return res.status(400).json({
          error:
            "Order ID and amount are required."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(orderId);

      const snapshot =
        await orderRef.get();

      if (!snapshot.exists) {
        return res.status(404).json({
          error: "Order not found."
        });
      }

      const order =
        snapshot.data();

      if (
        order.userId !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            "This order does not belong to you."
        });
      }

      await orderRef.update({
        paymentMethod:
          "mpesa",

        paymentStatus:
          "pending_verification",

        paymentAmount:
          Number(amount),

        mpesaReference:
          mpesaReference || "",

        paymentSubmittedAt:
          admin.firestore.FieldValue.serverTimestamp()
      });

      res.json({
        message:
          "M-Pesa payment submitted for verification."
      });

    } catch (error) {
      console.error(
        "M-Pesa payment error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   CASH PAYMENT
========================================== */

app.post(
  "/api/customer/cash-payment",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const {
        orderId
      } = req.body;

      if (!orderId) {
        return res.status(400).json({
          error:
            "Order ID is required."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(orderId);

      const snapshot =
        await orderRef.get();

      if (!snapshot.exists) {
        return res.status(404).json({
          error:
            "Order not found."
        });
      }

      const order =
        snapshot.data();

      if (
        order.userId !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            "This order does not belong to you."
        });
      }

      await orderRef.update({
        paymentMethod:
          "cash",

        paymentStatus:
          "cash_on_delivery"
      });

      res.json({
        message:
          "Cash payment selected."
      });

    } catch (error) {
      console.error(
        "Cash payment error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   MODERATOR PAYMENT VERIFICATION
========================================== */

app.patch(
  "/api/moderator/orders/:orderId/payment",
  requireModerator,
  async (req, res) => {
    try {
      const {
        paymentStatus
      } = req.body;

      const allowed = [
        "paid",
        "rejected"
      ];

      if (
        !allowed.includes(
          paymentStatus
        )
      ) {
        return res.status(400).json({
          error:
            "Invalid payment status."
        });
      }

      const orderRef =
        db
          .collection("orders")
          .doc(
            req.params.orderId
          );

      const snapshot =
        await orderRef.get();

      if (!snapshot.exists) {
        return res.status(404).json({
          error:
            "Order not found."
        });
      }

      await orderRef.update({
        paymentStatus,

        paymentVerifiedAt:
          admin.firestore.FieldValue.serverTimestamp(),

        paymentVerifiedBy:
          req.user.uid
      });

      res.json({
        message:
          `Payment ${paymentStatus}.`
      });

    } catch (error) {
      console.error(
        "Payment verification error:",
        error
      );

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* ==========================================
   SERVER
========================================== */

app.listen(
  PORT,
  () => {
    console.log(
      `Amir Chap Chap Backend LIVE on port ${PORT}`
    );
  }
);
