const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK using Environment Variables
const privateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  : undefined;

if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && privateKey) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: privateKey,
    }),
  });
  console.log('Firebase Admin initialized successfully.');
} else {
  console.warn('Firebase environment variables are missing or incomplete.');
}

// 1. Root Route (Fixes the 404 on Render)
app.get('/', (req, res) => {
  res.status(200).send('Amir Chap Chap Backend is running.');
});

// 2. Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date() });
});

// 3. Bootstrap Admin Route (Creates initial admin user securely)
app.post('/api/bootstrap-admin', async (req, res) => {
  const bootstrapSecret = req.headers['x-bootstrap-secret'];

  // Verify authorization secret
  if (!bootstrapSecret || bootstrapSecret !== process.env.BOOTSTRAP_SECRET) {
    return res.status(403).json({ error: 'Unauthorized: Invalid bootstrap secret key.' });
  }

  const { email, password, displayName } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    // Create Firebase Auth user
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: displayName || 'Admin User',
    });

    // Assign custom admin claim
    await admin.auth().setCustomUserClaims(userRecord.uid, { admin: true });

    // Store admin metadata in Firestore
    const db = admin.firestore();
    await db.collection('users').doc(userRecord.uid).set({
      email: userRecord.email,
      role: 'admin',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.status(201).json({
      message: 'Admin user created successfully.',
      uid: userRecord.uid,
      email: userRecord.email,
    });
  } catch (error) {
    console.error('Error creating admin user:', error);
    return res.status(500).json({ error: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
