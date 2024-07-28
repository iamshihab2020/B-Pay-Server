const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_NAME}:${process.env.DB_KEY}@cluster2024.kjdp6b2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster2024`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const userCollection = client.db("b_pay").collection("users");

    // JWT API
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // User Registration API
    app.post("/users", async (req, res) => {
      try {
        const { name, email, pin, role } = req.body;
        const query = { email };
        const existingUser = await userCollection.findOne(query);

        if (existingUser) {
          return res.send({ message: "User already exists", insertedId: null });
        }

        // Hash the PIN before saving
        const saltRounds = 10;
        const hashedPin = await bcrypt.hash(pin, saltRounds);

        const user = {
          name, // Use 'name' instead of 'names'
          email,
          pin: hashedPin,
          role: role || "user", // Default role to 'user'
        };

        const result = await userCollection.insertOne(user);
        res.send(result);
      } catch (error) {
        console.error("Error inserting user:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // User Login API
    app.post("/login", async (req, res) => {
      try {
        const { email, pin } = req.body;
        const user = await userCollection.findOne({ email });

        if (!user) {
          return res.status(400).send({ message: "User not found" });
        }

        // Compare hashed PIN with the input PIN
        const isMatch = await bcrypt.compare(pin, user.pin);

        if (!isMatch) {
          return res.status(400).send({ message: "Invalid credentials" });
        }

        // Generate JWT token
        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.ACCESS_TOKEN_SECRET,
          {
            expiresIn: "1h",
          }
        );

        res.send({ token });
      } catch (error) {
        console.error("Error during login:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.get("/users", async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        res.send(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("B-Pay is running");
});

app.listen(port, () => {
  console.log(`B-Pay is running on port ${port}`);
});
