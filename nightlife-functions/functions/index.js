/**
 * This file now contains TWO functions.
 * 1. createStaffUser: Creates a new user and their profile.
 * 2. removeStaffMember: Deletes a user from Auth and Firestore.
 */

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

admin.initializeApp();

// --- Function 1: Create Staff User ---
// This function remains the same.
exports.createStaffUser = onRequest({ cors: true }, async (req, res) => {
    if (req.method !== "POST") {
        return res.status(405).send({ error: "Method Not Allowed" });
    }
    if (
        !req.headers.authorization ||
        !req.headers.authorization.startsWith("Bearer ")
    ) {
        return res.status(401).send({ error: "Unauthorized: No token provided." });
    }

    const idToken = req.headers.authorization.split("Bearer ")[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const callerUid = decodedToken.uid;
        const adminDoc = await admin.firestore().collection("admins").doc(callerUid).get();
        if (!adminDoc.exists) {
            return res.status(403).send({ error: "Permission Denied" });
        }

        const { email, password, name, role } = req.body;
        if (!email || !password || !name || !role) {
            return res.status(400).send({ error: "Missing required fields." });
        }

        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: name,
        });

        const staffDocRef = admin.firestore().collection("staff").doc(userRecord.uid);
        await staffDocRef.set({
            name: name,
            role: role,
            uid: userRecord.uid,
        });

        return res.status(200).send({ success: true, message: `User ${name} created.` });
    } catch (error) {
        console.error("Error in createStaffUser:", error);
        if (error.code === "auth/email-already-exists") {
            return res.status(409).send({ error: "The email address is already in use by another account." });
        }
        return res.status(500).send({ error: "Internal Server Error" });
    }
});

// --- Function 2: Remove Staff Member ---
exports.removeStaffMember = onRequest({ cors: true }, async (req, res) => {
    if (req.method !== "POST") {
        return res.status(405).send({ error: "Method Not Allowed" });
    }
    if (
        !req.headers.authorization ||
        !req.headers.authorization.startsWith("Bearer ")
    ) {
        return res.status(401).send({ error: "Unauthorized: No token provided." });
    }

    const idToken = req.headers.authorization.split("Bearer ")[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const callerUid = decodedToken.uid;
        const adminDoc = await admin.firestore().collection("admins").doc(callerUid).get();
        if (!adminDoc.exists) {
            return res.status(403).send({ error: "Permission Denied" });
        }

        const { uidToRemove } = req.body;
        if (!uidToRemove) {
            return res.status(400).send({ error: "Missing uidToRemove field." });
        }

        // Prevent a manager from deleting themselves
        if (callerUid === uidToRemove) {
            return res.status(400).send({ error: "You cannot remove yourself." });
        }

        // Delete user from Firebase Authentication
        await admin.auth().deleteUser(uidToRemove);

        // Delete user's document from Firestore 'staff' collection
        await admin.firestore().collection("staff").doc(uidToRemove).delete();

        // Optional: Also remove them from the 'admins' list if they are one
        const adminRef = admin.firestore().collection("admins").doc(uidToRemove);
        const adminDocToRemove = await adminRef.get();
        if (adminDocToRemove.exists) {
            await adminRef.delete();
        }

        return res.status(200).send({ success: true, message: `User ${uidToRemove} has been removed.` });

    } catch (error) {
        console.error("Error in removeStaffMember:", error);
        if (error.code === 'auth/user-not-found') {
            return res.status(404).send({ error: "User to remove not found in Authentication." });
        }
        return res.status(500).send({ error: "Internal Server Error" });
    }
});
