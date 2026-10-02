const SessionHandler = require("./session");
const ProfileHandler = require("./profile");
const BenefitsHandler = require("./benefits");
const ContributionsHandler = require("./contributions");
const AllocationsHandler = require("./allocations");
const MemosHandler = require("./memos");
const ResearchHandler = require("./research");
const tutorialRouter = require("./tutorial");
const ErrorHandler = require("./error").errorHandler;

const index = (app, db) => {

    "use strict";

    const sessionHandler = new SessionHandler(db);
    const profileHandler = new ProfileHandler(db);
    const benefitsHandler = new BenefitsHandler(db);
    const contributionsHandler = new ContributionsHandler(db);
    const allocationsHandler = new AllocationsHandler(db);
    const memosHandler = new MemosHandler(db);
    const researchHandler = new ResearchHandler(db);

    // Middleware to check if a user is logged in
    const isLoggedIn = sessionHandler.isLoggedInMiddleware;

    //Middleware to check if user has admin rights
    const isAdmin = sessionHandler.isAdminUserMiddleware;

    // The main page of the app
    app.get("/", sessionHandler.displayWelcomePage);

    // Login form
    app.get("/login", sessionHandler.displayLoginPage);
    app.post("/login", sessionHandler.handleLoginRequest);

    // Signup form
    app.get("/signup", sessionHandler.displaySignupPage);
    app.post("/signup", sessionHandler.handleSignup);

    // Logout page
    app.get("/logout", sessionHandler.displayLogoutPage);

    // The main page of the app
    app.get("/dashboard", isLoggedIn, sessionHandler.displayWelcomePage);

    // Profile page
    app.get("/profile", isLoggedIn, profileHandler.displayProfile);
    app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);

    // Contributions Page
    app.get("/contributions", isLoggedIn, contributionsHandler.displayContributions);
    app.post("/contributions", isLoggedIn, contributionsHandler.handleContributionsUpdate);

    // Benefits Page
    app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
    app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
    /* Fix for A7 - checks user role to implement  Function Level Access Control
     app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
     app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
     */

    // Allocations Page
    app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);

    // Memos Page
    app.get("/memos", isLoggedIn, memosHandler.displayMemos);
    app.post("/memos", isLoggedIn, memosHandler.addMemos);

    // Handle redirect for learning resources link
    // Fix for A01 Broken Access Control (open redirect, CWE-601): the link
    // used to carry the full destination URL, so anyone could craft a
    // NodeGoat link that bounced users to a phishing site. Links now name a
    // resource and the server looks up its address, so the destination never
    // comes from the request.
    const LEARNING_RESOURCES = {
        "traditional-iras": "https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"
    };
    app.get("/learn", isLoggedIn, (req, res) => {
        const resource = String(req.query.resource || "");
        if (!Object.prototype.hasOwnProperty.call(LEARNING_RESOURCES, resource)) {
            return res.status(400).send("Unknown learning resource");
        }
        return res.redirect(LEARNING_RESOURCES[resource]);
    });

    // Research Page
    app.get("/research", isLoggedIn, researchHandler.displayResearch);

    // Mount tutorial router
    app.use("/tutorial", tutorialRouter);

    // Error handling middleware
    app.use(ErrorHandler);
};

module.exports = index;
