// We reuse this import in order to have access to the `body` property in requests
const express = require("express");

// ℹ️ Responsible for the messages you see in the terminal as requests are coming in
// https://www.npmjs.com/package/morgan
const logger = require("morgan");

// ℹ️ Needed when we deal with cookies (we will when dealing with authentication)
// https://www.npmjs.com/package/cookie-parser
const cookieParser = require("cookie-parser");

const session = require("express-session");

// ℹ️ Serves a custom favicon on each request
// https://www.npmjs.com/package/serve-favicon
const favicon = require("serve-favicon");

const MongoStore = require('connect-mongo')

// ℹ️ global package used to `normalize` paths amongst different operating systems
// https://www.npmjs.com/package/path
const path = require("path");

// Middleware configuration
module.exports = (app) => {
  // In development environment the app logs
  app.use(logger("dev"));

  // To have access to `body` property in the request
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  app.use(
    session({                                 // session takes a couple of settings
      secret: process.env.COOKIE_SECRET,      // for example: Hohfaivnr8474930rfnvoh0egw
      cookie: {                               // session takes a couple of settings
        maxAge: 24 * 60 * 60 * 1000,          //One day old // in miliseconds
              },          
        saveUninitialized: false,
        resave: false,
        store: MongoStore.create({
          mongoUrl: process.env.MONGODB_URI,  // || "mongodb://localhost/cookies",
          ttl: 24 * 60 * 60,                  // in seconds
        }),
    })
  );
  // Normalizes the path to the views folder
  app.set("views", path.join(__dirname, "..", "views"));
  // Sets the view engine to handlebars
  app.set("view engine", "hbs");
  // Handles access to the public folder
  app.use(express.static(path.join(__dirname, "..", "public")));

  // Handles access to the favicon
  app.use(favicon(path.join(__dirname, "..", "public", "images", "favicon.ico")));
};
