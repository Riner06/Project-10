const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'Rest API for user management',
    },
    servers: [
      {
        url: 'http://localhost:3000',
      },
    ],
  },
  apis: ['./rest-api/index.js'],
}

const app = express()

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

const THESECRET = 'secret of secrets';

const {getDBConnnection} = require("./server_connection");

const bodyParser = require("body-parser")


app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

const requireAuth = (req, res, next) => {
  let authHeader = req.headers["authorization"] 
  
  if (authHeader === undefined) {
    return res.status(401).send("Auth token missing.")
  }
  
  let token = authHeader.slice(7);

  let decoded
  try {
  
    decoded = jwt.verify(token, THESECRET)
  } catch (err) {

    console.error(err) 

    res.status(401).send("Invalid auth token")
  }

  next();
}
/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     description: Returns a list of all users
 *     responses:
 *       200:
 *         description: A list of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   username:
 *                     type: string
 *                   first_name:
 *                     type: string
 *                   last_name:
 *                     type: string
 */

 
app.get("/users",requireAuth, async function (req, res) {
  let connection = await getDBConnnection()
  let sql = `SELECT * FROM users`   
  let [results] = await connection.execute(sql)

  //res.json() skickar resultat som JSON till klienten
  res.json(results)

})
/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Get a user by ID
 *     description: Returns a single user by ID
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the user to retrieve
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A user object
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 username:
 *                   type: string
 *                 first_name:
 *                   type: string
 *                 last_name:
 *                   type: string
 */
app.get("/users/:id",requireAuth, async function(req, res){
  let connection = await getDBConnnection()
  let sql = `SELECT * FROM users WHERE id = ?`   
  //Varför behövde jag lägga till [req.params.id]? 
  let [results] = await connection.execute(sql, [req.params.id])

  //res.json() skickar resultat som JSON till klienten
  console.log(req.params.id)
  res.json(results)
})


async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;    
};

const isValidUser = (req, res, next) => {
  const { username,password } = req.body;
  const errors = [];

  if(!username || username.length < 1){
    errors.push("Username is required and must be at least one character")
  }

  if(!password || password.length < 6){
    errors.push("Password is required and must be at least six characters")
  }

  if(errors.length > 0)
    return res.status(422).json({errors});

  next();
}

const isValidLogin = (req, res, next) => {
  const { username, password} = req.body;
  const errors = [];

  if(!username || username.length < 1){
    errors.push("Username is required and must be at least one character")
  }

  if(!password || password.length < 6){
    errors.push("Password is required and must be at least six characters")
  }

  if(errors.length > 0)
    return res.status(422).json({errors});

  next();
}

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Create a new user
 *     description: Creates a new user with the provided information. Passwords are hashed before being stored.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 username:
 *                   type: string
 *                 first_name:
 *                   type: string
 *                 last_name:
 *                   type: string
 *                 password:
 *                   type: string
 */
app.post("/users", requireAuth, isValidUser, async function (req, res) {
  let connection = await getDBConnnection()
  try {
    const new_user = req.body;
    
    let hash = await hashPassword(new_user.password);
    new_user.password = hash;
    // new_user.id = users.length;
    const result = await connection.query(
      "INSERT INTO users (username, first_name, last_name, password) VALUES (?, ?, ?, ?)",
      [new_user.username, new_user.first_name, new_user.last_name, new_user.password]
    );
    new_user.id = result[0].insertId; 
    new_user.password=undefined;
    res.status(201).json(new_user);
  
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
  });
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login a user
 *     description: Authenticates a user and returns a JWT token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token for authentication
 *       401:
 *         description: Invalid credentials
 *       400:
 *         description: User not found
 */
app.post("/login", isValidLogin, async function (req, res) {
  let connection = await getDBConnnection();
  let sql = `SELECT * FROM users WHERE username = ?`;
  let [users] = await connection.execute(sql, [req.body.username]);
  let foundUser = users[0];

  try {

    if (!foundUser) {
      return res.status(400).json({ error: "Användaren finns inte" });
    }
    
    const isPasswordValid = await bcrypt.compare(req.body.password, foundUser.password);
    
    if (isPasswordValid) {
      let payload = {
        sub: foundUser.id,
        name: foundUser.first_name
      };
      
      let token = jwt.sign(payload, 'secret of secrets');
      res.json(token);
      console.log("Du är inloggad!");
      res.status(200);
    } else {
      res.status(401).json({ error: "Felaktigt lösenord" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
/**
 * @swagger
 * /users/{id}:
 *   put:
 *     summary: Update a user by ID
 *     description: Updates a user's information by ID. Passwords are hashed before being updated.
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the user to update
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 username:
 *                   type: string
 *                 first_name:
 *                   type: string
 *                 last_name:
 *                   type: string
 *                 password:
 *                   type: string
 *       404:
 *         description: User not found
 *       400:
 *         description: Bad request
 */ 
app.put("/users/:id", requireAuth, isValidUser, async function (req, res) {
  let connection = await getDBConnnection()
  
  try {
    const userId = req.params.id;
    const new_user = req.body;
    
    let hash = await hashPassword(new_user.password);

    const result = await connection.query(
      `UPDATE users SET username='${new_user.username}', first_name='${new_user.first_name}', last_name='${new_user.last_name}', password='${hash}' WHERE id=${userId}`

    );
    
    
    if (result[0].affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    new_user.password=undefined;

    new_user.id = userId; 
    res.status(200).json(new_user);
  
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


const port = 3000
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`)
})
