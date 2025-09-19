const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const conn = require('../db');

// Register page


// Register POST


// Login page
router.get('/login', (req, res) => {
  res.render('login');
});

// Login POST
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  conn.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length > 0) {
      const match = await bcrypt.compare(password, results[0].password);
      if (match) {
        req.session.userId = results[0].id;
        res.redirect('/dashboard');
      } else {
        res.send("Wrong password");
      }
    } else {
      res.send("User not found");
    }
  });
});

// Dashboard Page
router.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.render('dashboard');
});

router.post('/preview', (req, res) => {
  const {
    full_name, job_title, phone, email,
    website, card_type, color_primary, color_text
  } = req.body;

  if (!req.session.userId) return res.redirect('/login');

  res.render(`cards/card${card_type}`, {
    full_name,
    job_title,
    phone,
    email,
    website,
    color_primary,
    color_text
  });
});


module.exports = router;
