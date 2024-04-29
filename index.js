const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

//middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.i4cqwjk.mongodb.net/?retryWrites=true&w=majority`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// const products = require("./products.json");
// app.get("/products", (req, res) => {
//   res.send(products);
// });

const verifyJWT = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).send("unauthorized user");
  }
  const token = header.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
    if (err) {
      return res.status(401).send({ message: "token_not_valid" });
    }
    req.decoded = decoded;
    next();
  });
};

const verifyRefreshToken = (refreshToken) => {
  return new Promise((resolve, reject) => {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      function (err, decoded) {
        if (err) {
          reject(err); // Reject the promise with the error
        } else {
          resolve(decoded); // Resolve the promise with the decoded value
        }
      }
    );
  });
};

async function run() {
  try {
    const productCollection = client.db("e-Trade").collection("products");
    const cartCollection = client.db("e-Trade").collection("cart");
    const usersCollection = client.db("e-Trade").collection("users");

    app.post("/token", async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const findUser = await usersCollection.findOne(query);
      if (findUser) {
        if (user?.password === findUser?.password) {
          // Create access token
          const accessToken = jwt.sign(
            { email: user.email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "300h" }
          );

          // Create refresh token
          const refreshToken = jwt.sign(
            { email: user.email },
            process.env.REFRESH_TOKEN_SECRET
          );
          res.status(200).send({ accessToken, refreshToken });
        } else {
          res.status(400).send({ message: "Password dose not matched" });
        }
      } else {
        res.status(403).send({ message: "User not found" });
      }
    });

    app.post("/refreshToken", async (req, res) => {
      console.log("hit refresh token");
      const refreshToken = req.body.refreshToken;

      try {
        const decoded = await verifyRefreshToken(refreshToken);
        const email = decoded; // Assuming the decoded value is the email
        console.log(email, refreshToken);
        if (email) {
          // Create access token
          const accessToken = jwt.sign(
            { email: email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "300h" }
          );

          // Create refresh token
          const refreshToken = jwt.sign(
            { email: email },
            process.env.REFRESH_TOKEN_SECRET
          );
          res.status(200).send({ accessToken, refreshToken });
        }
      } catch (error) {
        console.error("Error verifying refresh token:", error);
        res
          .status(401)
          .send({ success: false, message: "Invalid refresh token" });
      }
    });

    app.get("/getUserInfo", verifyJWT, async (req, res) => {
      const email = req.decoded.email;
      console.log(email);
      const query = { email: email };
      const result = await usersCollection.findOne(query);
      res.send(result);
    });

    app.post("/register", async (req, res) => {
      const user = req.body;
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    app.get("/products", verifyJWT, async (req, res) => {
      const user = req.decoded;
      const query = {};
      const products = await productCollection.find(query).toArray();
      res.send(products);
    });

    app.get("/product/:_id", async (req, res) => {
      const id = req.query._id;
      const query = { id };
      const product = await productCollection.findOne(query);
      res.send(product);
    });

    app.get("/cart", verifyJWT, async (req, res) => {
      const user = req.decoded;
      const query = {};
      const result = await cartCollection.find(query).toArray();
      res.send(result);
    });
    app.post("/cart", async (req, res) => {
      const product = req.body;
      const result = await cartCollection.insertOne(product);
      res.send(result);
    });

    app.delete("/cartDelete/:_id", async (req, res) => {
      const _id = req.params._id;
      const query = { _id: new ObjectId(_id) };
      const result = await cartCollection.deleteOne(query);
      res.send(result);
    });
  } catch (error) {
    console.error("Error fetching database:", error);
    res.status(500).send("Internal Server Error");
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server running");
});

app.listen(port, () => {
  console.log("server running on port", port);
});
