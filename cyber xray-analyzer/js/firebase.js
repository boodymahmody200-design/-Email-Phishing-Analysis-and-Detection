/* ============================================================
   X-Ray Analyzer — Firebase Configuration & Auth Manager
   js/firebase.js
   ============================================================
   SETUP INSTRUCTIONS:
   1. Go to https://console.firebase.google.com
   2. Create a new project named "X-Ray Analyzer"
   3. Go to Project Settings > General > Your Apps > Add Web App
   4. Copy the firebaseConfig values below
   5. Enable Authentication > Email/Password
   6. Enable Firestore Database (start in test mode)
   7. Replace the placeholder values below with your real config
   ============================================================ */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore, doc, getDoc, setDoc, addDoc, collection,
         query, where, orderBy, limit, getDocs, deleteDoc, updateDoc, serverTimestamp }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// ── YOUR FIREBASE CONFIG ────────────────────────────────────
// Replace these values with your actual Firebase project config
const firebaseConfig = {
  apiKey: "AIzaSyBd7HMfffagxRJsOzBv3eq4IUGTkxcV3Pw",
  authDomain: "saas-e1f35.firebaseapp.com",
  projectId: "saas-e1f35",
  storageBucket: "saas-e1f35.firebasestorage.app",
  messagingSenderId: "18811083926",
  appId: "1:18811083926:web:9289c5f8910da35518f6b7"
};
// ───────────────────────────────────────────────────────────

const app = initializeApp(firebaseConfig);
// (auth instance handled via fbAuth below)
const db   = getFirestore(app);
const fbAuth = getAuth(app);

// ── Auth helpers ────────────────────────────────────────────

export async function login(email, password) {
  const cred = await signInWithEmailAndPassword(fbAuth, email, password);
  const userDoc = await getDoc(doc(db, 'users', cred.user.uid));
  if (!userDoc.exists()) throw new Error('Account not found in system. Contact administrator.');
  const userData = userDoc.data();
  if (!userData.active) throw new Error('Your account has been deactivated. Contact administrator.');
  return { uid: cred.user.uid, ...userData };
}

export function logout() {
  return signOut(fbAuth);
}

export function onAuth(callback) {
  return onAuthStateChanged(fbAuth, async (user) => {
    if (!user) { callback(null); return; }
    try {
      const snap = await getDoc(doc(db, 'users', user.uid));
      if (!snap.exists() || !snap.data().active) { callback(null); return; }
      callback({ uid: user.uid, ...snap.data() });
    } catch { callback(null); }
  });
}

// ── User management (admin only) ───────────────────────────

export async function getUsers() {
  const snap = await getDocs(collection(db, 'users'));
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

export async function createUser(uid, data) {
  await setDoc(doc(db, 'users', uid), {
    ...data,
    role: data.role || 'client',
    active: true,
    createdAt: serverTimestamp(),
    scanCount: 0
  });
}

export async function toggleUser(uid, active) {
  await updateDoc(doc(db, 'users', uid), { active });
}

export async function deleteUser(uid) {
  await deleteDoc(doc(db, 'users', uid));
}

// ── Scan History ────────────────────────────────────────────

export async function saveScan(uid, scanData) {
  await addDoc(collection(db, 'scans'), {
    uid,
    ...scanData,
    createdAt: serverTimestamp()
  });
  // Increment user scan count
  const userRef = doc(db, 'users', uid);
  const snap = await getDoc(userRef);
  if (snap.exists()) {
    await updateDoc(userRef, { scanCount: (snap.data().scanCount || 0) + 1 });
  }
}

export async function getUserScans(uid, limitN = 20) {
  const q = query(
    collection(db, 'scans'),
    where('uid', '==', uid),
    orderBy('createdAt', 'desc'),
    limit(limitN)
  );
  const snap = await getDocs(q);
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

export async function getAllScans(limitN = 50) {
  const q = query(collection(db, 'scans'), orderBy('createdAt', 'desc'), limit(limitN));
  const snap = await getDocs(q);
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

export async function deleteScan(id) {
  await deleteDoc(doc(db, 'scans', id));
}

export { fbAuth, db };
