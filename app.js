//jshint esversion:6
require('dotenv').config();
currentYear = new Date().getFullYear();
const {parse: flatParse, stringify} = require('flatted');
let {PythonShell} = require('python-shell');
const express = require("express");
var multer  = require('multer');
const download = require('download');
const path = require("path");
const fs = require('fs');
const { parse } = require('csv-parse/sync');
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

function getPythonPath() {
  const venvWin  = path.join(__dirname, ".venv", "Scripts", "python.exe");
  const venvUnix = path.join(__dirname, ".venv", "bin", "python");
  if (fs.existsSync(venvWin))  return venvWin;
  if (fs.existsSync(venvUnix)) return venvUnix;
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

app.get("/secrets", function(req, res) {
  if (!req.isAuthenticated()) return res.redirect("/login");

  req.session.randomResult = null;

  const defaultAccuracies = {
    knn_bin_acc:  "0.9760", knn_mul_acc:  "0.9740",
    rf_bin_acc:   "0.9741", rf_mul_acc:   "0.9731",
    cnn_bin_acc:  "0.9583", cnn_mul_acc:  "0.9506",
    lstm_bin_acc: "0.9562", lstm_mul_acc: "0.9591"
  };
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
  const s = req.session;
  res.render("secrets_2", {
    knn_bin_cls:  s.knn_bin_cls  || "",
    knn_mul_cls:  s.knn_mul_cls  || "",
    knn_desc:     s.knn_desc     || "",
    knn_bin_acc:  s.knn_bin_acc  || "0.9760",
    knn_mul_acc:  s.knn_mul_acc  || "0.9740",
    rf_bin_cls:   s.rf_bin_cls   || "",
    rf_mul_cls:   s.rf_mul_cls   || "",
    rf_desc:      s.rf_desc      || "",
    rf_bin_acc:   s.rf_bin_acc   || "0.9741",
    rf_mul_acc:   s.rf_mul_acc   || "0.9731",
    cnn_bin_cls:  s.cnn_bin_cls  || "",
    cnn_mul_cls:  s.cnn_mul_cls  || "",
    cnn_desc:     s.cnn_desc     || "",
    cnn_bin_acc:  s.cnn_bin_acc  || "0.9583",
    cnn_mul_acc:  s.cnn_mul_acc  || "0.9506",
    lstm_bin_cls: s.lstm_bin_cls || "",
    lstm_mul_cls: s.lstm_mul_cls || "",
    lstm_desc:    s.lstm_desc    || "",
    lstm_bin_acc: s.lstm_bin_acc || "0.9562",
    lstm_mul_acc: s.lstm_mul_acc || "0.9591"
  });
});

app.get("/secrets_2_ready", function(req, res) {
  res.json({ ready: !!(req.session && req.session.randomReady) });
});

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
    stderrParser: line => null
  };

  PythonShell.run('nids_parameter_updated.py', options, (err, response) => {
    const raw = (response && response[0]) ? response[0].trim() : null;

    if (!raw) {
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
      return res.render("paramsecrets", { prediction: null, error: "Script output (not JSON): " + raw.slice(0, 400) });
    }
  });
});

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

    console.log("=== CSV UPLOAD: model =", submitted_model, "| file =", submitted_csv_file);

    const options = {
      pythonPath: getPythonPath(),
      scriptPath: __dirname,
      args: [submitted_model, submitted_csv_file],
      stderrParser: line => null
    };

    PythonShell.run('nids_csv_updated.py', options, (err, response) => {
      if (err) {
        console.log("=== PYTHON ERROR:", err);
        return res.end("Prediction failed!");
      }

      console.log("=== PYTHON RESPONSE:", response);

      const resultPath = path.join(__dirname, 'Uploaded_files', submitted_csv_file);
      console.log("=== RESULT FILE PATH:", resultPath);
      console.log("=== FILE EXISTS:", fs.existsSync(resultPath));

      let rows = [];
      try {
        const fileContent = fs.readFileSync(resultPath, 'utf8');
        rows = parse(fileContent, { columns: true, skip_empty_lines: true });
        console.log("=== PARSED ROWS:", rows.length);
        console.log("=== FIRST ROW KEYS:", rows[0] ? Object.keys(rows[0]) : "no rows");
      } catch (readErr) {
        console.log("=== FILE READ ERROR:", readErr.message);
        return res.end("Error reading result file: " + readErr.message);
      }

      const totalRows = rows.length;
      let normalCount = 0, attackCount = 0;
      const breakdown = { Normal: 0, Dos: 0, Probe: 0, R2L: 0, U2R: 0 };

      rows.forEach(row => {
        const bin   = (row['binary class'] || '').trim();
        const multi = (row['multi class']  || '').trim();
        if (bin === 'Normal') normalCount++;
        else attackCount++;
        if (breakdown[multi] !== undefined) breakdown[multi]++;
      });

      console.log("=== STATS: total=", totalRows, "normal=", normalCount, "attack=", attackCount);
      console.log("=== BREAKDOWN:", breakdown);
      console.log("=== RENDERING csv_results...");

      res.render('csv_results', {
        rows,
        totalRows,
        normalCount,
        attackCount,
        breakdown,
        model:    submitted_model,
        filename: submitted_csv_file
      }, function(renderErr, html) {
        if (renderErr) {
          console.log("=== RENDER ERROR:", renderErr);
          return res.end("Render error: " + renderErr.message);
        }
        console.log("=== RENDER SUCCESS, sending HTML...");
        res.send(html);
      });
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

app.get('/download/:filename', (req, res) => {
  const filePath = path.join(__dirname, 'Uploaded_files', req.params.filename);
  res.download(filePath);
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