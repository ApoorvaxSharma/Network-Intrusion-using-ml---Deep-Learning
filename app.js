//jshint esversion:6
require('dotenv').config();

currentYear = new Date().getFullYear();
const {parse, stringify} = require('flatted');
let {PythonShell} = require('python-shell');
const express = require("express");
var multer  = require('multer');
const download = require('download');
const path = require("path");
const fs = require('fs');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// BUG 2 FIX: session secret moved to environment variable
app.use(session({
  secret: process.env.SESSION_SECRET || "fallback-dev-secret-change-in-production",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DB_LINK)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) { done(null, user.id); });
passport.deserializeUser(function(id, done) {
  User.findById(id).then(user => done(null, user)).catch(err => done(err, null));
});

passport.use(new GoogleStrategy({
  clientID:     process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL:  process.env.CALL_BACK_URL,
  userProfileUrl: process.env.URL
}, async function(accessToken, refreshToken, profile, cb) {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({ googleId: profile.id, username: profile.displayName });
    }
    return cb(null, user);
  } catch (err) {
    return cb(err, null);
  }
}));

// BUG 1 FIX: cross-platform Python path — tries venv first, falls back to system python3/python
function getPythonPath() {
  const venvWin  = path.join(__dirname, ".venv", "Scripts", "python.exe");
  const venvUnix = path.join(__dirname, ".venv", "bin", "python");
  if (fs.existsSync(venvWin))  return venvWin;
  if (fs.existsSync(venvUnix)) return venvUnix;
  // fall back to system Python (works in Docker / Heroku / Mac)
  return process.platform === "win32" ? "python" : "python3";
}

submitted_csv_file = "";
var storage = multer.diskStorage({
  destination: function(req, file, callback) { callback(null, './Uploaded_files'); },
  filename:    function(req, file, callback) {
    submitted_csv_file = file.originalname;
    callback(null, file.originalname);
  }
});
var upload = multer({ storage: storage }).single('myfile');

app.get("/", function(req, res) { res.render("home"); });

// BUG 3 FIX: auth guard added; BUG 4 FIX: results stored in req.session (per-user)
app.get("/secrets", function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");

  // Reset session results for this request
  req.session.randomResult = null;

  const defaultAccuracies = {
    knn_bin_acc:  "0.9760", knn_mul_acc:  "0.9740",
    rf_bin_acc:   "0.9741", rf_mul_acc:   "0.9731",
    cnn_bin_acc:  "0.9583", cnn_mul_acc:  "0.9506",
    lstm_bin_acc: "0.9562", lstm_mul_acc: "0.9591"
  };
  // Pre-render with empty results; secrets_2 will show populated data
  Object.assign(req.session, defaultAccuracies,
    { knn_bin_cls:"", knn_mul_cls:"", knn_desc:"",
      rf_bin_cls:"",  rf_mul_cls:"",  rf_desc:"",
      cnn_bin_cls:"", cnn_mul_cls:"", cnn_desc:"",
      lstm_bin_cls:"",lstm_mul_cls:"",lstm_desc:"" });

  res.render("secrets");

  const options = {
    pythonPath: getPythonPath(),
    scriptPath: __dirname,
    args: [],
    stderrParser: line => null
  };
  PythonShell.run('nids_random_updated.py', options, (err, response) => {
    if (err) { console.log("Python error:", err); return; }
    if (response) {
      // BUG 4 FIX: store in session, not globals
      req.session.knn_bin_cls  = stringify(response[0]).slice(2,-2);
      req.session.knn_mul_cls  = stringify(response[1]).slice(2,-2);
      req.session.knn_desc     = stringify(response[2]).slice(2,-2);
      req.session.rf_bin_cls   = stringify(response[3]).slice(2,-2);
      req.session.rf_mul_cls   = stringify(response[4]).slice(2,-2);
      req.session.rf_desc      = stringify(response[5]).slice(2,-2);
      req.session.cnn_bin_cls  = stringify(response[6]).slice(2,-2);
      req.session.cnn_mul_cls  = stringify(response[7]).slice(2,-2);
      req.session.cnn_desc     = stringify(response[8]).slice(2,-2);
      req.session.lstm_bin_cls = stringify(response[9]).slice(2,-2);
      req.session.lstm_mul_cls = stringify(response[10]).slice(2,-2);
      req.session.lstm_desc    = stringify(response[11]).slice(2,-2);
      req.session.randomReady  = true;
      req.session.save();
    }
  });
});

app.get("/secrets_2", function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.render("secrets_2");
});

// BUG 8 FIX: /secrets_2_ready endpoint now exists — secrets.ejs polling works
app.get("/secrets_2_ready", function(req, res) {
  res.json({ ready: !!(req.session && req.session.randomReady) });
});

// BUG 3 FIX: auth guard added to paramsecrets and parameters
app.get("/paramsecrets", function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.render("paramsecrets", { prediction: null, error: null });
});

app.post("/parameters", function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const b = req.body;
  const args = [
    b.protocol_type, b.service, b.flag,
    b.logged_in, b.count,
    b.srv_serror_rate, b.srv_rerror_rate, b.same_srv_rate, b.diff_srv_rate,
    b.dst_host_count, b.dst_host_srv_count,
    b.dst_host_same_srv_rate, b.dst_host_diff_srv_rate,
    b.dst_host_same_src_port_rate, b.dst_host_serror_rate, b.dst_host_rerror_rate
  ];

  const options = {
    pythonPath: getPythonPath(),
    scriptPath: __dirname,
    args: args,
    stderrParser: line => null   // ignore stderr (sklearn/TF warnings) — don't treat as errors
  };

  PythonShell.run('nids_parameter_updated.py', options, (err, response) => {
    const raw = (response && response[0]) ? response[0].trim() : null;

    if (!raw) {
      // Script crashed before printing anything (missing import, etc.)
      const hint = err ? (err.message || JSON.stringify(err)) : "No output from prediction script.";
      return res.render("paramsecrets", { prediction: null, error: "Script failed to start — " + hint });
    }

    try {
      const result = JSON.parse(raw);
      if (result.error) {
        return res.render("paramsecrets", { prediction: null, error: result.error });
      }
      return res.render("paramsecrets", { prediction: result, error: null });
    } catch (parseErr) {
      // Not valid JSON — show raw output for debugging
      return res.render("paramsecrets", { prediction: null, error: "Script output (not JSON): " + raw.slice(0, 400) });
    }
  });
});

// BUG 5 FIX: duplicate GET /csv removed — only one handler with auth guard
app.get("/csv", function(req, res) {
  if (req.isAuthenticated()) res.render("csv");
  else res.redirect("/login");
});

final_ans = "";
app.post('/uploadjavatpoint', function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  upload(req, res, function(err) {
    if (err) return res.end("Error uploading file.");
    const submitted_model = req.body.selected_model;
    const options = {
      pythonPath: getPythonPath(),
      scriptPath: __dirname,
      args: [submitted_model, submitted_csv_file],
      stderrParser: line => null
    };
    PythonShell.run('nids_csv_updated.py', options, (err, response) => {
      if (err) { console.log(err); return res.end("Prediction failed!"); }
      if (response) {
        final_ans = stringify(response[0]).slice(2,-2);
        res.end("Prediction completed successfully!");
      }
    });
  });
});

l = "completed!!";
app.get('/index', (req, res) => {
  if (l == final_ans) { res.render('index'); }
});

app.get('/download-file', (req, res) => {
  const dlPath = './Uploaded_files/' + submitted_csv_file;
  res.download(dlPath);
});

app.get("/features",  (req, res) => res.render("features"));
app.get("/attacks",   (req, res) => res.render("attacks"));
app.get("/about",     (req, res) => res.render("about"));
app.get("/knn_bin_table",  (req, res) => res.render("knn_bin_table"));
app.get("/rf_bin_table",   (req, res) => res.render("rf_bin_table"));
app.get("/cnn_bin_table",  (req, res) => res.render("cnn_bin_table"));
app.get("/lstm_bin_table", (req, res) => res.render("lstm_bin_table"));
app.get("/knn_table",      (req, res) => res.render("knn_table"));
app.get("/rf_table",       (req, res) => res.render("rf_table"));
app.get("/cnn_table",      (req, res) => res.render("cnn_table"));
app.get("/lstm_table",     (req, res) => res.render("lstm_table"));
app.get("/stats",          (req, res) => res.render("stats"));
app.get("/parameters",     (req, res) => res.render("parameters"));
app.get("/contact",        (req, res) => res.render("contact"));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get("/auth/google/NIDS",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) { res.redirect("/submit"); }
);

app.get("/login",    (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) res.render("submit");
  else res.redirect("/login");
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
  if (submitted_csv_file != "") {
    const delPath = './Uploaded_files/' + submitted_csv_file;
    fs.unlink(delPath, (err) => {
      if (err) console.log(err);
      else console.log('file deleted');
      submitted_csv_file = "";
    });
  }
});

app.post("/register", function(req, res) {
  User.register({ username: req.body.username }, req.body.password, function(err, user) {
    if (err) { console.log(err); res.redirect("/register"); }
    else {
      passport.authenticate("local")(req, res, function() { res.redirect("/submit"); });
    }
  });
});

app.post("/login", function(req, res) {
  const user = new User({ username: req.body.username, password: req.body.password });
  req.login(user, function(err) {
    if (err) console.log(err);
    else passport.authenticate("local")(req, res, function() { res.redirect("/submit"); });
  });
});

let port = process.env.PORT;
if (port == null || port == "") port = 3000;
app.listen(port, function() { console.log("Server started on port " + port); });