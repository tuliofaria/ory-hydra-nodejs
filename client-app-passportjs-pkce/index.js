const express = require("express");
const session = require("express-session");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");
const path = require("path");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 5556;

// OAuth 2.0 client configurations
const clientId = process.env.CLIENT_ID || "idoftheclient3";
const clientSecret = process.env.CLIENT_SECRET || "my-secret";
const redirectUri =
  process.env.REDIRECT_URI || "http://localhost:5556/callback";
const hydraPublicUrl = process.env.HYDRA_PUBLIC_URL || "http://localhost:4444";
const hydraAdminUrl = process.env.HYDRA_ADMIN_URL || "http://hydra:4445";
const apiUrl = process.env.API_URL || "http://localhost:3000/api";

// Application configurations
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session configuration
app.use(
  session({
    secret: "my-session-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // In production, use secure: true with HTTPS
  })
);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// OAuth 2.0 strategy configuration
passport.use(
  "oauth2",
  new OAuth2Strategy(
    {
      authorizationURL: `${hydraPublicUrl}/oauth2/auth`,
      tokenURL: `${hydraPublicUrl}/oauth2/token`,
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL: redirectUri,
      scope: ["openid", "profile", "email", "offline"],
      pkce: true,
      state: true,
    },
    (accessToken, refreshToken, params, profile, done) => {
      // Saving tokens and user information
      const userInfo = {
        accessToken,
        refreshToken,
        idToken: params.id_token,
        expiresAt: Date.now() + params.expires_in * 1000,
        tokenType: params.token_type,
      };

      // Fetch user information via userinfo endpoint
      axios
        .get(`${hydraPublicUrl}/userinfo`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        })
        .then((response) => {
          userInfo.profile = response.data;
          return done(null, userInfo);
        })
        .catch((error) => {
          console.error("Error fetching user information:", error.message);
          return done(null, userInfo);
        });
    }
  )
);

// User serialization and deserialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    // Check if the token is expired
    if (req.user.expiresAt < Date.now()) {
      return refreshToken(req, res, next);
    }
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect("/login");
};

// Function to refresh token
const refreshToken = (req, res, next) => {
  if (!req.user.refreshToken) {
    // If no refresh token, redirect to login
    req.logout(() => {
      res.redirect("/login");
    });
    return;
  }

  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("refresh_token", req.user.refreshToken);
  params.append("client_id", clientId);
  params.append("client_secret", clientSecret);

  axios
    .post(`${hydraPublicUrl}/oauth2/token`, params)
    .then((response) => {
      const data = response.data;

      // Update tokens in the user object
      req.user.accessToken = data.access_token;
      req.user.refreshToken = data.refresh_token || req.user.refreshToken;
      req.user.expiresAt = Date.now() + data.expires_in * 1000;

      next();
    })
    .catch((error) => {
      console.error("Error refreshing token:", error.message);
      req.logout(() => {
        res.redirect("/login");
      });
    });
};

// Routes
app.get("/", (req, res) => {
  res.render("index", {
    isAuthenticated: req.isAuthenticated(),
    userInfo: req.isAuthenticated() ? req.user.profile : null,
  });
});

// Route to start the login process
app.get("/login", passport.authenticate("oauth2"));

// OAuth 2.0 callback route
app.get(
  "/callback",
  passport.authenticate("oauth2", { failureRedirect: "/login-failure" }),
  (req, res) => {
    const redirectTo = req.session.returnTo || "/";
    delete req.session.returnTo;
    res.redirect(redirectTo);
  }
);

// Route for login failure
app.get("/login-failure", (req, res) => {
  res.status(401).render("error", {
    message: "Authentication failed. Please try again.",
  });
});

// Route to access protected data
app.get("/protected-data", isAuthenticated, async (req, res) => {
  try {
    const response = await axios.get(`${apiUrl}/protected-resources`, {
      headers: {
        Authorization: `Bearer ${req.user.accessToken}`,
      },
    });

    res.render("protected-data", { data: response.data });
  } catch (error) {
    console.error("Error accessing protected data:", error.message);

    // If the error is authentication-related, try refreshing the token
    if (error.response && error.response.status === 401) {
      return refreshToken(req, res, () => {
        res.redirect("/protected-data");
      });
    }

    res.status(500).render("error", {
      message: `Error accessing protected resources: ${error.message}`,
    });
  }
});

// Route for logout
app.get("/logout", (req, res) => {
  // Revoke the token in Hydra (optional)
  if (req.isAuthenticated() && req.user.accessToken) {
    const params = new URLSearchParams();
    params.append("token", req.user.accessToken);
    params.append("token_type_hint", "access_token");
    params.append("client_id", clientId);
    params.append("client_secret", clientSecret);

    axios.post(`${hydraPublicUrl}/oauth2/revoke`, params).catch((error) => {
      console.error("Error revoking token:", error.message);
    });
  }

  // Perform local logout
  req.logout(() => {
    res.redirect("/");
  });
});

// User information
app.get("/profile", isAuthenticated, (req, res) => {
  res.render("profile", { user: req.user });
});

// Start the server
app.listen(port, () => {
  console.log(`Client application running on port ${port}`);
});
