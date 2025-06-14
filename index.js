const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const port = 3000;
require('dotenv').config();

const app = express();
app.use(express.json());

let db;

async function connecToMongoDB() {
    const uri = 'mongodb://localhost:27017/';
    const client = new MongoClient(uri);

    try {
        await client.connect();
        console.log('Connected to MongoDB');
        
        db = client.db('GoRideDB');
    } catch (error) {
        console.error('Error:', error);
    }
}
connecToMongoDB();

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

// --- Register and Login --- //


// POST /register - Create a new user or driver
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.post('/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ error: "Username, password, and role are required" });
        }

        if (!['user', 'driver'].includes(role)) {
            return res.status(400).json({ error: "Invalid role. Must be 'user' or 'driver'" });
        }

        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(409).json({ error: "Username already exists" });
        }

        // Hash the password before storing
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const user = { username, password: hashedPassword, role };

        const result = await db.collection('users').insertOne(user);
        res.status(201).json({ id: result.insertedId, message: `${role} registered successfully` });
    } catch (error) {
        res.status(500).json({ error: "Failed to register" });
    }
});

// POST /login - Authenticate a user with role
const jwt = require('jsonwebtoken');

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" });
        }

        const user = await db.collection('users').findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(200).json({ message: "Login successful", role: user.role, token });
    } catch (error) {
        res.status(500).json({ error: "Failed to login" });
    }
});

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
};

// Authorization middleware (RBAC)
const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role))
        return res.status(403).json({ error: "Forbidden" });
    next();
};

// --- User Endpoints --- //

// POST /rides - Create a new ride
app.post('/rides', async (req, res) => {
    try {
        const { id, destination, status } = req.body;
        if (!id || !destination || !status) {
            return res.status(400).json({ error: "User ID, destination and status are required" });
        }

        const ride = { id, destination, status };
        const result = await db.collection('rides').insertOne(ride);

        res.status(201).json({ rideID: result.insertedId });
    } catch (error) {
        res.status(500).json({ error: "Failed to create ride" });
    }
});

// PATCH /rides/car/:rideID - Update a ride's car
app.patch('/rides/car/:rideID', async (req, res) => {
    try {
        const { rideID } = req.params;
        const { car } = req.body;

        if (!ObjectId.isValid(rideID)) {
            return res.status(400).json({ error: "Invalid ride ID format" });
        }

        const result = await db.collection('rides').updateOne(
            { _id: new ObjectId(rideID) },
            { $set: { car } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found" });
        }

        res.status(200).json({ updated: result.modifiedCount });

    } catch (error) {
        res.status(400).json({ error: "Invalid ride ID or data" });
    }
});

// POST /rides/pay/:rideID - Pay for a ride
app.post('/rides/pay/:rideID', async (req, res) => {
    try {
        const { rideID } = req.params;
        const { paymentMethod, amount } = req.body;

        if (!ObjectId.isValid(rideID) || !paymentMethod || !amount) {
            return res.status(400).send("Bad Request");
        }

        const result = await db.collection('rides').updateOne(
            { _id: new ObjectId(rideID), paymentStatus: { $ne: 'Paid' } },
            { $set: { paymentMethod, paymentStatus: 'Paid', amount } }
        );

        if (result.matchedCount === 0) {
            return res.status(402).send("Payment Required");
        }

        res.status(200).send("OK");
        } catch (error) {
        res.status(500).send("Internal Server Error");
        }
    });

// GET /rides/:id/history - Fetch ride history for a user
app.get('/rides/:id/history', async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid user ID format" });
        }

        const rides = await db.collection('rides').find({ id: id }).toArray();
        if (rides.length === 0) {
            return res.status(404).json({ error: "No rides found for this user" });
        }
        res.status(200).json(rides);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch ride history" });
    }
});

// --- Driver Endpoints --- //

// PATCH /rides/:rideID/accept - Accept a ride
app.patch('/rides/:rideID/accept', async (req, res) => {
    try {
        const { rideID } = req.params;
        const { id } = req.body;

        if (!ObjectId.isValid(rideID) || !id) {
            return res.status(400).json({ error: "Invalid ride ID or driver ID" });
        }

        const result = await db.collection('rides').updateOne(
            { _id: new ObjectId(rideID), status: 'Pending' },
            { $set: { status: 'Accepted', id } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found or already accepted" });
        }

        res.status(200).json({ message: "Ride accepted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to accept ride" });
    }
});

// PATCH /rides/:rideID/cancel - Cancel a ride
app.patch('/rides/:rideID/cancel', async (req, res) => {
    try {
        const { rideID } = req.params;
        const { id } = req.body;

        if (!ObjectId.isValid(rideID) || !id) {
            return res.status(400).json({ error: "Invalid ride ID or driver ID" });
        }

        const result = await db.collection('rides').updateOne(
            { _id: new ObjectId(rideID), status: 'Accepted' },
            { $set: { status: 'Cancelled', id } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found or already cancelled" });
        }

        res.status(200).json({ message: "Ride cancelled successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to cancel ride" });
    }
});

// GET /rides/:id/history - Fetch ride history for a driver
app.get('/rides/:id/history', async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid driver ID format" });
        }

        const rides = await db.collection('rides').find({ id: id }).toArray();
        if (rides.length === 0) {
            return res.status(404).json({ error: "No rides found for this driver" });
        }
        res.status(200).json(rides);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch ride history" });
    }
});

// --- Admin Endpoints --- //

// GET /admin/accounts - Fetch all user accounts
app.get('/admin/accounts', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const users = await db.collection('users').find().toArray();
        if (users.length === 0) {
            return res.status(403).json({ error: "No user accounts found" });
        }
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch user accounts" });
    }
});

// POST /admin/accounts - Create a new user account
app.post('/admin/accounts', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ error: "Username, password, and role are required" });
        }

        if (!['user', 'driver', 'admin'].includes(role)) {
            return res.status(400).json({ error: "Invalid role. Must be 'user' or 'driver' or 'admin'" });
        }

        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(409).json({ error: "Username already exists" });
        }

        // Hash the password before storing
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const result = await db.collection('users').insertOne({ username, password: hashedPassword, role });
        res.status(201).json({ id: result.insertedId, message: `${role} registered successfully` });
    } catch (error) {
        res.status(500).json({ error: "Failed to register" });
    }
});

// PATCH /admin/accounts/:id - Update a user account
app.patch('/admin/accounts/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { username, password, role } = req.body;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid user ID format" });
        }

        const updateData = {};
        if (username) updateData.username = username;
        if (password) updateData.password = await bcrypt.hash(password, saltRounds);
        if (role) updateData.role = role;

        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json({ message: "User account updated successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to update user account" });
    }
});

// DELETE /admin/accounts/:id - Delete a user account
app.delete('/admin/accounts/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid user ID format" });
        }

        const result = await db.collection('users').deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json({ message: "User account deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to delete user account" });
    }
});

// GET /admin/reports - Fetch all ride reports
app.get('/admin/reports', async (req, res) => {
    try {
        const rides = await db.collection('rides').find().toArray();
        if (rides.length === 0) {
            return res.status(403).json({ error: "No ride reports found" });
        }
        res.status(200).json(rides);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch ride reports" });
    }
});
