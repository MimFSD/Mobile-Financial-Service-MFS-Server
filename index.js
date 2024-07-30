const express = require("express");
const cors = require('cors');
require('dotenv').config();

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
// const bodyParser = require('body-parser');



const app = express();
const port = process.env.PORT || 5000;


// Midleware
app.use(cors({
    origin: [
        'http://localhost:5173',
        'https://readypay.vercel.app'
    ],
    credentials: true
}));
app.use(express.json());

// MongoDB Conection Method
const uri = `mongodb+srv://${process.env.ENV_READYPAY_USER}:${process.env.ENV_READYPAY_PASSWORD}@cluster0.6e55rfm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});





async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        // Database name Creat
        const userCollection = client.db('ReadyPay').collection('user-info');

        // ***************  Veryfy secure JWT API Funtionality ********************

        // JWT Token generation
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.send({ token });
        });

        // Middleware to verify token
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'unauthorized access' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'unauthorized access' });
                }
                req.decoded = decoded;
                next();
            });
        };


        // *****************    Admin Funtionality  *******************


        // Aproval admin
        app.patch('/activate/:id', verifyToken, async (req, res) => {
            const userId = req.params.id;
            const result = await userCollection.updateOne(
                { _id: new ObjectId(userId) },
                { $set: { status: 'active', balance: 40 } }
            );
            res.send(result);
        });


        //  ***************  user funtionality **************

        // Registration User
        app.post('/register', async (req, res) => {
            const { name, pin, mobile, email, role } = req.body;

            const existingUser = await userCollection.findOne({ email });
            if (existingUser) {
                return res.status(400).send({ message: 'User already exists' });
            }

            const hashedPin = await bcrypt.hash(pin, 10);
            const newUser = { name, pin: hashedPin, mobile, email, role, status: 'pending', balance: 0 };
            const result = await userCollection.insertOne(newUser);
            res.send(result);
        });


        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            try {
                const user = await userCollection.findOne({ $or: [{ email: identifier }, { mobile: identifier }] });
                if (!user) {
                    return res.status(400).send({ error: 'Invalid email or phone number' });
                }
                const isMatch = await bcrypt.compare(pin, user.pin);
                if (!isMatch) {
                    return res.status(400).send({ error: 'Invalid PIN' });
                }
                const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
                res.send({ token });
            } catch (error) {
                console.error('Server Error:', error);  // Log the actual error
                res.status(500).send({ error: 'Server error' });
            }
        });



        // User Logout
        app.post('/logout', (req, res) => {
            res.send({ message: 'Logged out successfully' });
        });



        // Send Money functionality
        app.post('/send-money', verifyToken, async (req, res) => {
            const { senderId, receiverId, amount, pin } = req.body;

            if (amount < 50) {
                return res.status(400).send({ error: 'Minimum transaction amount is 50 Taka' });
            }

            const fee = amount > 100 ? 5 : 0;
            const totalDeducted = amount + fee;

            try {
                const sender = await userCollection.findOne({ _id: new ObjectId(senderId) });
                const receiver = await userCollection.findOne({ _id: new ObjectId(receiverId) });

                if (!sender || !receiver) {
                    return res.status(404).send({ error: 'Sender or receiver not found' });
                }

                const isMatch = await bcrypt.compare(pin, sender.pin);
                if (!isMatch) {
                    return res.status(400).send({ error: 'Invalid PIN' });
                }

                if (sender.balance < totalDeducted) {
                    return res.status(400).send({ error: 'Insufficient balance' });
                }

                // Perform the transaction
                await userCollection.updateOne(
                    { _id: new ObjectId(senderId) },
                    { $inc: { balance: -totalDeducted } }
                );

                await userCollection.updateOne(
                    { _id: new ObjectId(receiverId) },
                    { $inc: { balance: amount } }
                );

                res.send({ message: 'Transaction successful', fee });
            } catch (error) {
                console.error('Server Error:', error);
                res.status(500).send({ error: 'Server error' });
            }
        });
















        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);




// Main Server Function
app.get('/', (req, res) => {
    res.send('Mobile Financial Service is Started')
})

app.listen(port, () => {
    console.log(`Financial user Port : ${port}`);
})