"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
// const csrf = require('csurf');
const nunjucks = require("nunjucks"); // Template engine (replaces the abandoned swig)
const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
const http = require("http");
const { marked } = require("marked"); // v4+ uses a named export
const app = express(); // Web framework to handle routing requests
const routes = require("./app/routes");
const { port, db: dbUrl, cookieSecret } = require("./config/config"); // Application config properties
/*
// Fix for A6-Sensitive Data Exposure
// Load keys for establishing secure HTTPS connection
const fs = require("fs");
const https = require("https");
const path = require("path");
// The key pair is not committed (it was removed: private keys must never be
// in source control). Generate your own and point these variables at it.
const httpsOptions = {
    key: fs.readFileSync(process.env.HTTPS_KEY_PATH),
    cert: fs.readFileSync(process.env.HTTPS_CERT_PATH)
};
*/

// mongodb driver 3.x passes a client to the callback; the database named
// in the connection string is then opened with client.db()
MongoClient.connect(dbUrl, { useNewUrlParser: true, useUnifiedTopology: true }, (err, client) => {
    if (err) {
        console.log("Error: DB: connect");
        console.log(err);
        process.exit(1);
    }
    const db = client.db();
    console.log(`Connected to the database`);

    // Fix for A05 Security Misconfiguration: send the standard security
    // headers ZAP reported missing (Content-Security-Policy, X-Frame-Options,
    // X-Content-Type-Options and others) and stop advertising Express via
    // X-Powered-By. helmet 2 was listed but never enabled, and its old
    // dependencies were themselves vulnerable.
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                // Tutorial pages embed OWASP talks from YouTube
                "frame-src": ["https://www.youtube.com"],
                // The app is served over plain HTTP in this demo, so asking
                // browsers to upgrade every request to HTTPS would break it
                "upgrade-insecure-requests": null
            }
        }
    }));

    // Adding/ remove HTTP Headers for security
    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Express middleware to populate "req.body" so we can access POST variables
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        // Mandatory in Express v4
        extended: false
    }));

    // Enable session management using express middleware
    app.use(session({
        // genid: (req) => {
        //    return genuuid() // use UUIDs for session IDs
        //},
        secret: cookieSecret,
        // Both mandatory in Express v4
        saveUninitialized: true,
        resave: true
        /*
        // Fix for A5 - Security MisConfig
        // Use generic cookie name
        key: "sessionId",
        */

        /*
        // Fix for A3 - XSS
        // TODO: Add "maxAge"
        cookie: {
            httpOnly: true
            // Remember to start an HTTPS server to get this working
            // secure: true
        }
        */

    }));

    /*
    // Fix for A8 - CSRF
    // Enable Express csrf protection
    app.use(csrf());
    // Make csrf token available in templates
    app.use((req, res, next) => {
        res.locals.csrftoken = req.csrfToken();
        next();
    });
    */

    // Register templating engine
    // Fix for A03 Injection (XSS, CWE-79) and A06: swig is abandoned with an
    // unfixed CVE and ran with autoescape off, so any user data in a page was
    // rendered as live HTML. Nunjucks escapes every {{ value }} by default;
    // only trusted output is marked "| safe" in the templates.
    nunjucks.configure(`${__dirname}/app/views`, {
        autoescape: true,
        express: app
    });
    app.set("view engine", "html");
    // Fix for A5 - Security MisConfig
    // TODO: make sure assets are declared before app.use(session())
    app.use(express.static(`${__dirname}/app/assets`));


    // Initializing marked library
    // Fix for A9 - Insecure Dependencies
    marked.setOptions({
        sanitize: true
    });
    app.locals.marked = marked;

    // Application routes
    routes(app, db);

    // Insecure HTTP connection
    http.createServer(app).listen(port, () => {
        console.log(`Express http server listening on port ${port}`);
    });

    /*
    // Fix for A6-Sensitive Data Exposure
    // Use secure HTTPS protocol
    https.createServer(httpsOptions, app).listen(port, () => {
        console.log(`Express http server listening on port ${port}`);
    });
    */

});
