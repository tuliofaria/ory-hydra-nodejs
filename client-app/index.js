const express = require("express");
const session = require("express-session");
const fetch = require("node-fetch");
const path = require("path");

const app = express();
const port = process.env.PORT || 5555;

// OAuth 2.0 client settings
const clientId = process.env.CLIENT_ID || "someidforthisclient";
const clientSecret = process.env.CLIENT_SECRET || "my-secret";
const redirectUri =
  process.env.REDIRECT_URI || "http://localhost:5555/callback";
const hydraPublicUrl = process.env.HYDRA_PUBLIC_URL || "http://localhost:4444";
const apiUrl = process.env.API_URL || "http://localhost:3000/api";

// Application settings
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session settings
app.use(
  session({
    secret: "my-session-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // In production, use secure: true with HTTPS
  })
);

// Middleware to check if the user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.accessToken) {
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect("/login");
};

// Home page route
app.get("/", (req, res) => {
  res.render("index", {
    isAuthenticated: !!req.session.accessToken,
    userInfo: req.session.userInfo || null,
  });
});

// Route to start the login flow
app.get("/login", (req, res) => {
  console.log("====== state", req.session.returnTo);

  const authUrl = new URL(`${hydraPublicUrl}/oauth2/auth`);
  authUrl.searchParams.append("client_id", clientId);
  authUrl.searchParams.append("redirect_uri", redirectUri);
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("scope", "openid profile email offline");
  authUrl.searchParams.append(
    "state",
    Buffer.from(
      JSON.stringify({
        returnTo: req.session.returnTo || "/",
      })
    ).toString("base64")
  );

  res.redirect(authUrl.toString());
});

// Route to handle the OAuth 2.0 callback
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).render("error", {
      message: "Authorization code missing",
    });
  }

  try {
    // Exchange the authorization code for an access token
    const tokenResponse = await fetch(`${hydraPublicUrl}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${clientId}:${clientSecret}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenResponse.status !== 200) {
      throw new Error(tokenData.error_description || "Error obtaining token");
    }

    // Save tokens in the session
    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken = tokenData.refresh_token;
    req.session.idToken = tokenData.id_token;

    // Get user information using the access token
    const userInfoResponse = await fetch(`${hydraPublicUrl}/userinfo`, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    if (userInfoResponse.status === 200) {
      req.session.userInfo = await userInfoResponse.json();
    }

    // Redirect to the original page
    let returnTo = "/";
    if (state) {
      try {
        const decodedState = JSON.parse(
          Buffer.from(state, "base64").toString()
        );
        returnTo = decodedState.returnTo || "/";
      } catch (e) {
        console.error("Error decoding state:", e);
      }
    }

    res.redirect(returnTo);
  } catch (error) {
    console.error("Error in callback:", error);
    res.status(500).render("error", {
      message: `Authentication error: ${error.message}`,
    });
  }
});

// Route to access protected API resources
app.get("/protected-data", isAuthenticated, async (req, res) => {
  try {
    console.log(req.session);
    const response = await fetch(`${apiUrl}/protected-resources`, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
      },
    });

    if (response.status === 401) {
      // Token expired, try refreshing
      if (req.session.refreshToken) {
        const refreshed = await refreshAccessToken(req);
        if (refreshed) {
          return res.redirect(req.originalUrl);
        }
      }
      return res.redirect("/login");
    }

    const data = await response.json();
    res.render("protected-data", { data });
  } catch (error) {
    console.error("Error accessing protected data:", error);
    res.status(500).render("error", {
      message: `Error accessing protected resources: ${error.message}`,
    });
  }
});

// Function to refresh the access token
async function refreshAccessToken(req) {
  try {
    const tokenResponse = await fetch(`${hydraPublicUrl}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(
          `${clientId}:${clientSecret}`
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: req.session.refreshToken,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenResponse.status !== 200) {
      return false;
    }

    // Update tokens in the session
    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken =
      tokenData.refresh_token || req.session.refreshToken;

    return true;
  } catch (error) {
    console.error("Error refreshing token:", error);
    return false;
  }
}

// Route to log out
app.get("/logout", async (req, res) => {
  // Revoke tokens in Hydra (if necessary)
  if (req.session.accessToken) {
    try {
      await fetch(`${hydraPublicUrl}/oauth2/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${Buffer.from(
            `${clientId}:${clientSecret}`
          ).toString("base64")}`,
        },
        body: new URLSearchParams({
          token: req.session.accessToken,
          token_type_hint: "access_token",
        }),
      });
    } catch (error) {
      console.error("Error revoking token:", error);
    }
  }

  // Clear the session
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`Client application running on port ${port}`);
});
