const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const path = require("path");
const axios = require("axios").default;

const app = express();
const port = process.env.PORT || 3000;
const hydraAdminUrl = "http://localhost:4445"; //"http://hydra:4445";

// Express configuration
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Error middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "An error occurred on the server" });
});

// Login route
app.get("/login", async (req, res, next) => {
  try {
    // Get the login challenge
    const challenge = req.query.login_challenge;
    if (!challenge) {
      return res.status(400).json({ error: "login_challenge is required" });
    }

    const response = await axios.get(
      `${hydraAdminUrl}/oauth2/auth/requests/login?login_challenge=${challenge}`
    );

    // Verify the login challenge with Hydra
    const loginRequest = response.data;

    // If the user is already authenticated, accept the login automatically
    if (loginRequest.skip) {
      const acceptResponse = await fetch(
        `${hydraAdminUrl}/oauth2/auth/requests/login/accept`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            subject: loginRequest.subject,
            login_challenge: challenge,
          }),
        }
      );
      const acceptData = await acceptResponse.json();

      return res.redirect(acceptData.redirect_to);
    }

    // Render the login page
    res.render("login", {
      challenge,
      requestedScope: loginRequest.requested_scope,
      client: loginRequest.client,
    });
  } catch (error) {
    res.send(error);
  }
});

// Process the login form
app.post("/login", async (req, res, next) => {
  try {
    const { email, password, challenge } = req.body;

    // Here you would use your existing authentication system
    // This is just a simple example
    let userId = null;
    let loginAccepted = false;

    // Simulated authentication - replace with your real logic
    userId = email;
    loginAccepted = true;

    console.log({
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subject: userId,
        login_challenge: challenge,
      }),
    });

    // If login is successful, accept the challenge
    const acceptResponse = await fetch(
      `${hydraAdminUrl}/oauth2/auth/requests/login/accept?challenge=${challenge}`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subject: userId,
        }),
      }
    );

    const acceptData = await acceptResponse.json();

    console.log("acceptData.redirect_to);", acceptData);

    res.redirect(acceptData.redirect_to);
  } catch (error) {
    next(error);
  }
});

// Consent route
app.get("/consent", async (req, res, next) => {
  try {
    const challenge = req.query.consent_challenge;
    if (!challenge) {
      return res.status(400).json({ error: "consent_challenge is required" });
    }

    // Verify the consent challenge with Hydra
    const response = await fetch(
      `${hydraAdminUrl}/oauth2/auth/requests/consent?challenge=${challenge}`
    );
    const consentRequest = await response.json();

    // If the user has already given consent, accept automatically
    if (consentRequest.skip) {
      const acceptResponse = await fetch(
        `${hydraAdminUrl}/oauth2/auth/requests/consent/accept?challenge=${challenge}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_scope: consentRequest.requested_scope,
          }),
        }
      );
      const acceptData = await acceptResponse.json();

      console.log("consent", acceptData);

      return res.redirect(acceptData.redirect_to);
    }

    console.log(consentRequest.client);

    // Render the consent page
    res.render("consent", {
      challenge,
      requestedScope: consentRequest.requested_scope,
      client: consentRequest.client,
      user: consentRequest.subject,
    });
  } catch (error) {
    next(error);
  }
});

// Process the consent form
app.post("/consent", async (req, res, next) => {
  try {
    const { challenge, submit } = req.body;
    let scopes = req.body.scopes || [];

    // Convert to array if not already
    if (!Array.isArray(scopes)) {
      scopes = [scopes];
    }

    // If the user denies consent
    if (submit === "reject") {
      const rejectResponse = await fetch(
        `${hydraAdminUrl}/oauth2/auth/requests/consent/reject`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            consent_challenge: challenge,
            error: "access_denied",
            error_description: "The user denied access to their data",
          }),
        }
      );
      const rejectData = await rejectResponse.json();
      return res.redirect(rejectData.redirect_to);
    }

    // If the user accepts consent
    const acceptResponse = await fetch(
      `${hydraAdminUrl}/oauth2/auth/requests/consent/accept?challenge=${challenge}`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_scope: scopes,
          remember: false,
          remember_for: 3600, // Remember for 1 hour
        }),
      }
    );

    const acceptData = await acceptResponse.json();
    res.redirect(acceptData.redirect_to);
  } catch (error) {
    next(error);
  }
});

// Middleware to verify token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token not provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify the token with Hydra
    const introspectResponse = await fetch(
      `${hydraAdminUrl}/oauth2/introspect`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token,
          // these are the scopes we need in this endpoint
          scope: "openid profile email",
        }),
      }
    );

    const introspection = await introspectResponse.json();

    if (!introspection.active) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    // Add token information to the request
    req.oauth = introspection;
    next();
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ error: "Error validating token" });
  }
};

// Protected resources endpoint
app.get("/api/protected-resources", verifyToken, (req, res) => {
  // Here you can return real data from your application
  res.json({
    message: "Protected data accessed successfully!",
    user: req.oauth.sub,
    scope: req.oauth.scope,
    data: {
      item1: "Protected value 1",
      item2: "Protected value 2",
      timestamp: new Date().toISOString(),
    },
  });
});

// Start the server
app.listen(port, () => {
  console.log(`** Authentication server running on port ${port} xoxoxoxo`);
});
