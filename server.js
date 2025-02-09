/*******************************************************
 * server.js (Node.js + Express + PostgreSQL + Nodemailer)
 ********************************************************/
require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

/*******************************************************
 * 1) Connect to PostgreSQL via Pool
 *******************************************************/
const pool = new Pool({
  connectionString: process.env.DATABASE_URL // e.g. "postgres://user:pass@host:5432/dbname"
  // For local dev, you might need ssl: { rejectUnauthorized: false } if using Neon
  // ssl: { rejectUnauthorized: false },
});

/*******************************************************
 * 2) Middlewares
 *******************************************************/
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Cookie-based session
app.use(cookieSession({
  name: 'session',
  secret: 'supersecretpharmacy',
  maxAge: 24 * 60 * 60 * 1000
}));

/*******************************************************
 * 3) Allowed Emails for account creation
 *******************************************************/
const allowedEmails = [
  process.env.ALLOWED_EMAIL_1 || 'skychauhan98work@gmail.com',
  process.env.ALLOWED_EMAIL_2 || 'pindsbains@gmail.com'
];

/*******************************************************
 * 4) checkAuth
 * Ensures user is logged in
 *******************************************************/
function checkAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/index.html'); 
  }
  next();
}

/*******************************************************
 * 5) Authentication routes
 *******************************************************/
// POST /createaccount
app.post('/createaccount', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!allowedEmails.includes(email)) {
      return res.status(400).send('Email not allowed to create an account');
    }
    const hash = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    await client.query(`
      INSERT INTO users (email, passwordHash) VALUES ($1, $2)
    `, [email, hash]);
    client.release();

    return res.redirect('/index.html?accountCreated=1');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error creating account, maybe user exists');
  }
});

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const client = await pool.connect();
    const result = await client.query(`SELECT * FROM users WHERE email=$1`, [email]);
    client.release();

    if (result.rows.length === 0) {
      return res.status(401).send('No user found with that email.');
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.passwordhash);
    if (!match) {
      return res.status(401).send('Invalid password.');
    }

    // store session
    req.session.userId = user.id;
    req.session.email = user.email;

    return res.redirect('/dashboard.html');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error on login.');
  }
});

// GET /logout
app.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/index.html?loggedOut=1');
});

/*******************************************************
 * 6) Nodemailer Helper
 *******************************************************/
async function sendSignoffEmail(subject, bodyText) {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
  await transporter.sendMail({
    from: `"Langley Pharmacy" <${process.env.EMAIL_USER}>`,
    to: [allowedEmails[0], allowedEmails[1]],
    subject,
    text: bodyText
  });
}

/*******************************************************
 * 7) Common sign-off logic
 *******************************************************/
async function signoff(checklistType, date, signoffData) {
  // signoffData can have managerName, deputyName, directorName, fridgeTemperature, notes
  const client = await pool.connect();

  // see if row exists for that date + type
  let result = await client.query(`
    SELECT * FROM signoffs
    WHERE checklistType=$1 AND date=$2
  `, [checklistType, date]);

  if (result.rows.length === 0) {
    // Insert new
    await client.query(`
      INSERT INTO signoffs (
        checklistType, date, managerName, deputyName, directorName,
        overwritesUsed, signoffTimestamp, fridgeTemperature, notes
      )
      VALUES ($1, $2, $3, $4, $5, 0, NOW(), $6, $7)
    `, [
      checklistType, date,
      signoffData.managerName || null,
      signoffData.deputyName || null,
      signoffData.directorName || null,
      signoffData.fridgeTemperature || null,
      signoffData.notes || null
    ]);
    client.release();
    return { locked: false, overwrote: false };
  } else {
    // Already exists => check overwritesUsed
    const existing = result.rows[0];
    if (existing.overwritesused >= 2) {
      client.release();
      return { locked: true, overwrote: false };
    }
    let newOverwrites = existing.overwritesused + 1;
    await client.query(`
      UPDATE signoffs
      SET managerName=$3, deputyName=$4, directorName=$5,
          overwritesUsed=$6, signoffTimestamp=NOW(),
          fridgeTemperature=$7, notes=$8
      WHERE id=$1
    `, [
      existing.id, // $1
      // $2 is not used in the set but was in the select
      signoffData.managerName || existing.managername,
      signoffData.deputyName || existing.deputyname,
      signoffData.directorName || existing.directorname,
      newOverwrites,
      signoffData.fridgeTemperature || existing.fridgetemperature,
      signoffData.notes || existing.notes
    ]);
    client.release();
    return { locked: false, overwrote: true };
  }
}

/*******************************************************
 * 8) API routes for daily/weekly/monthly sign-off
 *******************************************************/
// DAILY
app.post('/api/signoff/daily', checkAuth, async (req, res) => {
  const { date, managerName, deputyName, fridgeTemperature, notes } = req.body;
  try {
    const { locked, overwrote } = await signoff('daily', date, {
      managerName, deputyName, fridgeTemperature, notes
    });
    if (locked) return res.status(403).send('Daily sign-off locked after 2 overwrites.');

    // Send email
    await sendSignoffEmail(
      overwrote ? `Daily Sign-Off Overwrite ${date}` : `Daily Sign-Off ${date}`,
      `Daily sign-off for ${date}\nManager: ${managerName}\nDeputy: ${deputyName}\n`
    );
    return res.redirect('/dashboard.html?dailySigned=1');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error signing off daily');
  }
});

// WEEKLY
app.post('/api/signoff/weekly', checkAuth, async (req, res) => {
  const { date, managerName, deputyName, notes } = req.body;
  try {
    const { locked, overwrote } = await signoff('weekly', date, {
      managerName, deputyName, notes
    });
    if (locked) return res.status(403).send('Weekly sign-off locked after 2 overwrites.');

    await sendSignoffEmail(
      overwrote ? `Weekly Sign-Off Overwrite ${date}` : `Weekly Sign-Off ${date}`,
      `Weekly sign-off for ${date}\nManager: ${managerName}\nDeputy: ${deputyName}\n`
    );
    res.redirect('/dashboard.html?weeklySigned=1');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error signing off weekly');
  }
});

// MONTHLY
app.post('/api/signoff/monthly', checkAuth, async (req, res) => {
  const { date, directorName, notes } = req.body;
  try {
    // Check if it's last weekday of the month
    const d = new Date(date);
    // last day of that month
    let lastDay = new Date(d.getFullYear(), d.getMonth() + 1, 0);
    // back up if it's Sat(6) or Sun(0)
    while (lastDay.getDay() === 6 || lastDay.getDay() === 0) {
      lastDay.setDate(lastDay.getDate() - 1);
    }
    const isoCheck = lastDay.toISOString().slice(0,10); 
    if (date !== isoCheck) {
      return res.status(400).send('Monthly sign-off only if last weekday of the month.');
    }

    const { locked, overwrote } = await signoff('monthly', date, {
      directorName, notes
    });
    if (locked) return res.status(403).send('Monthly sign-off locked after 2 overwrites.');

    await sendSignoffEmail(
      overwrote ? `Monthly Sign-Off Overwrite ${date}` : `Monthly Sign-Off ${date}`,
      `Monthly sign-off for ${date}\nDirector: ${directorName}\n`
    );
    res.redirect('/dashboard.html?monthlySigned=1');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error signing off monthly');
  }
});

/*******************************************************
 * 9) HISTORY (list signoffs)
 *******************************************************/
app.get('/api/history', checkAuth, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT id, checklistType, date, managerName, deputyName, directorName, 
             overwritesUsed, signoffTimestamp
      FROM signoffs
      ORDER BY date ASC
    `);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'failed to fetch signoffs' });
  }
});

/*******************************************************
 * 10) Start Server
 *******************************************************/
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
