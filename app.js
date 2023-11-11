const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const flash = require('express-flash');
const swaggerJsdoc = require("swagger-jsdoc");
const  swaggerUi = require("swagger-ui-express");

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
// app.use('/api-docs',swaggerUI.serve,swaggerUI.setup(docs));

const options = {
    definition: {
      openapi: "3.1.0",
      info: {
        title: "Home-pal Real Estate WEBAPP ",
        version: "0.1.0",
        description:
          "This is a real estate app Server made with NodeJs/Express Js and documented with swagger UI done by David Grace and Temiede Emmanuel",
        license: {
          name: "MIT",
          url: "https://spdx.org/licenses/MIT.html",
        },
        contact: {
          name: "Mainapp Page",
          url: "https://home-pal-smoky.vercel.app/",
          email: "emmanueltemiede@gmail.com",
        },
      },
      servers: [
        {
          url: "http://localhost:3000",
        },
      ],
    },
    apis: ["*.js"],
  };
  
  const specs = swaggerJsdoc(options);
  app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(specs)
  );

const db = new sqlite3.Database('./database.sqlite');

// Passport local strategy for user login
passport.use(new LocalStrategy(
    (username, password, done) => {
      db.get('SELECT * FROM users WHERE username = ?', username, (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect username or register if you dont have an account' });
        if (!bcrypt.compareSync(password, user.password)) return done(null, false, { message: 'Incorrect password or register if you dont have an account' });
        return done(null, user);
      });
    }
  ));
  
  // Passport serialization
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', id, (err, user) => {
      if (err) return done(err);
      done(null, user);
    });
  });
  
/**
 * @swagger
 * components:
 *   schemas:
 *     register:
 *       type: object
 *       required:
 *         - username
 *         - password
 *       properties:
 *         username:
 *           type: string
 *           description: The username you want to use
 *         password:
 *           type: string
 *           description: Your desired Password
 */
/**
 * @swagger
 * tags:
 *   name: REGISTERATION
 *   description: Registeration endpoint
 * /api/register:
 *   post:
 *     summary: Register eitheir a user or a tenants
 *     tags: [register]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/register'
 *     responses:
 *       200:
 *         description: You logged in Succesfull.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/register'
 *       500:
 *         description: Some server error
 *
 */
/**
 * @swagger
 * components:
 *   schemas:
 *     login:
 *       type: object
 *       required:
 *         - username
 *         - password
 *       properties:
 *         username:
 *           type: string
 *           description: The username you used to register
 *         password:
 *           type: string
 *           description: Your Password
 */
/**
 * @swagger
 * tags:
 *   name: LOGIN
 *   description: Login endpoint
 * /api/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [login]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/login'
 *     responses:
 *       200:
 *         description: You logged in succesfully.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/login'
 *       500:
 *         description: Some server error
 *
 */

// ... Passport configuration remains the same ...

// Registration route

// ... Passport configuration remains the same ...

// Registration route

  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/api/login');
  }
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the username already exists
    db.get('SELECT * FROM users WHERE username = ?', username, (err, existingUser) => {
        if (err) {
            console.error('Error checking username:', err);
            return res.status(500).json({ message: 'Error checking username.' });
        }

        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists.' });
        }

        const saltRounds = 10;
        bcrypt.genSalt(saltRounds, (err, salt) => {
            if (err) {
                console.error('Error generating salt:', err);
                return res.status(500).json({ message: 'Registration gensalt failed.' });
            }

            bcrypt.hash(password, salt, (err, hashedPassword) => {
                if (err) {
                    console.error('Error hashing password:', err);
                    return res.status(500).json({ message: 'Registration hash failed.', err });
                }

                db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
                    if (err) {
                        console.error('Error inserting into database:', err);
                        return res.status(500).json({ message: 'Registration insertion failed.' });
                    }
                    return res.status(201).json({ message: 'Registration successful.' });
                });
            });
        });
    });
});

// Login route
app.post('/api/login', passport.authenticate('local', {
    successRedirect: '/api/loginsuccesful',
    failureRedirect: '/api/loginerror',
    failureFlash: true,
}));
app.get('/api/loginsuccesful', (req, res) => {
    res.status(400).json({ message: "Login was succssful"});
});

app.get('/api/loginerror',  (req, res) => {
    res.status(401).json({ message: "The user's credentials were incorrect"});
});


// Logout route
app.get('/api/logout', ensureAuthenticated,(req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error logging out:', err);
            req.flash('error', 'Error logging out.');
        }
        res.redirect('/');
    });
});

// // Dashboard route
// app.get('/api/dashboard', ensureAuthenticated, (req, res) => {
//     const userId = req.user.id;

//     db.all('SELECT * FROM tasks WHERE user_id = ?', [userId], (err, tasks) => {
//         if (err) {
//             console.error('Error fetching tasks:', err);
//             req.flash('error', 'Error fetching tasks.');
//             return res.status(500).json({ message: 'Error fetching tasks.' });
//         }

//         res.status(200).json({ user: req.user, tasks: tasks });
//     });
// });


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
