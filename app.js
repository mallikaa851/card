import express from 'express';
import session from 'express-session';
import { removeBackground } from "@imgly/background-removal-node";
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import bodyParser from 'body-parser';
import { conn } from './db.js';
import multer from 'multer';
import fs from 'fs';
import QRCode from 'qrcode';
import tinycolor from "tinycolor2";

const router = express.Router();


const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('view engine', 'ejs'); 
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.json({ limit: '20mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));
app.use("/uploads/logos", express.static(path.join(__dirname, "public/uploads/logos")));
app.use('/uploads/qrs', express.static(path.join(__dirname, 'public/uploads/qrs')));


app.get('/login', (req, res) => {
  res.render('login'); 
});
app.use(session({
  secret: 'secret123',
  resave: false,
  saveUninitialized: true
}));

app.use((req, res, next) => {
  res.set('Cache-Control', 'must-revalidate, private');
  next();
});

app.get('/', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  conn.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }

    if (results.length > 0) {
      
      bcrypt.compare(password, results[0].password, (err, match) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Server error");
        }

        if (match) {
          req.session.userId = results[0].id;
          req.session.username = results[0].username; 
          res.redirect('/dashboard');
        } else {
          res.send("Wrong password");
        }
      });
    } else {
      res.send("User not found");
    }
  });
});

/*app.post('/login', (req, res) => {
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
});""*/

app.get('/register', (req, res) => {
  res.render('register'); 
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.send("All fields are required!");
  }

  conn.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.send('Database error');

    if (results.length > 0) {
      return res.send('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    conn.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword],
      (err, result) => {
        if (err) return res.send('Error creating user: ' + err);

        // User successfully created → session save
        req.session.userId = result.insertId;  // MySQL insertId
        req.session.username = username;

        res.redirect('/');
      }
    );
  });
});

// Multer config (already correct)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname,'public/uploads/logos')),
  filename:   (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Images only'));
    cb(null, true);
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('dashboard', {
    user: { username: req.session.username },
    userData: req.session.tempCard || {}
  });
});




// Temporary save route (form submit from dashboard)
app.post('/tempCard', upload.single('logo'), (req, res) => {
  req.session.tempCard = {
    full_name: req.body.full_name || "",
    job_title: req.body.job_title || "",
    phone: req.body.phone || "",
    address: req.body.address || "",
    email: req.body.email || "",
    website: req.body.website || "",
    license_no: req.body.license_no || "",
    card_type: req.body.card_type || "",
    color_primary: req.body.color_primary || "#ffffff",
    color_secondary: req.body.color_secondary || "#000000",
    color_text: req.body.color_text || "#000000",
    font_family: req.body.font_family || "Arial",
    font_size: req.body.font_size || "14",
    logo: req.file 
      ? "/uploads/logos/" + req.file.filename 
      : req.session.tempCard?.logo || null ,
    social_linkedin : req.body.social_linkedin,
    social_facebook: req.body.social_facebook,
    social_instagram: req.body.social_instagram,
    social_whatsapp: req.body.social_whatsapp,
    social_youtube: req.body.social_youtube,
    social_twitter: req.body.social_twitter
  };
  res.redirect("/preview");
});

app.post("/uploadCroppedLogo", (req, res) => {
  try {
    const { croppedImage } = req.body;
    const base64Data = croppedImage.replace(/^data:image\/png;base64,/, "");
    const filename = `logo-${Date.now()}.png`;
    const filepath = path.join(__dirname, "public/uploads/logos", filename);

    // Make sure folder exists
    const uploadDir = path.join(__dirname, "public/uploads/logos");
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

    // Save file synchronously
    fs.writeFileSync(filepath, base64Data, "base64");

    // Update session
    req.session.tempCard = req.session.tempCard || {};
    req.session.tempCard.logo = `/uploads/logos/${filename}`; // ✅ correct template string

    res.json({ success: true, logoPath: `/uploads/logos/${filename}` });
  } catch (err) {
    console.error("Error saving cropped logo:", err);
    res.json({ success: false });
  }
});


app.get('/preview', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');

  let cardData = req.session.tempCard;
  const cardOnly1 = req.query.cardOnly1 === 'true';

  if (req.query.id) {
    conn.query("SELECT * FROM cards WHERE id = ?", [req.query.id], (err, results) => {
      if (!err && results.length > 0) cardData = results[0];
      res.render('preview', { 
        user: { username: req.session.username }, 
        userData: cardData, 
        cardOnly: false,
        cardOnly1
      });
    });
  } else {
    res.render('preview', { 
      user: { username: req.session.username }, 
      userData: cardData, 
      cardOnly: false,
      cardOnly1
    });
  }
});



app.get('/card/:id', async (req, res) => {
  const cardId = req.params.id;

  conn.query("SELECT * FROM cards WHERE id = ?", [cardId], async (err, results) => {
    if (err || results.length === 0) return res.send("Card not found");

    const card = results[0];

    // Safety defaults
    const userData = {
      ...card,
      color_primary: card.color_primary || "#ffffff",
      color_secondary: card.color_secondary || "#000000",
      color_text: card.color_text || "#000000",
    };

    res.render('preview', { 
      userData, 
      cardOnly: true, 
      cardOnly1: true,
      user: { username: req.session.username || "Guest" } 
    });
  });
});

app.post('/saveCardFromPreview', upload.single('logo'), async (req, res) => {
  if (!req.session.userId || !req.session.tempCard) return res.redirect('/dashboard');

  try {
    const userData = req.session.tempCard;
    const font_size = userData.font_size ? parseInt(userData.font_size) : 14;
    const logo = userData.logo || null; 
    const includeQr = req.body.include_qr === 'on';

    const secondary = userData.color_secondary?.trim() !== "" 
        ? userData.color_secondary 
        : tinycolor(userData.color_primary).lighten(20).toString();
    const textColor = userData.color_text?.trim() !== "" 
        ? userData.color_text 
        : (tinycolor(userData.color_primary).isLight() ? "#000000" : "#ffffff");

    const insertSql = `
      INSERT INTO cards 
        (user_id, full_name, job_title, phone, email, address, website, license_no, card_type, color_primary, color_secondary, color_text, font_family, font_size, logo , social_linkedin, social_facebook, social_instagram,
    social_whatsapp, social_youtube, social_twitter)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      req.session.userId,
      userData.full_name, userData.job_title, userData.phone, userData.email,userData.address, userData.website, 
      userData.license_no,
      userData.card_type, userData.color_primary, secondary, textColor, userData.font_family, font_size, logo , 
      userData.social_linkedin, userData.social_facebook, userData.social_instagram, userData.social_whatsapp, 
      userData.social_youtube, userData.social_twitter
    ];

    const [result] = await new Promise((resolve, reject) => {
      conn.query(insertSql, values, (err, r) => err ? reject(err) : resolve([r]));
    });

    const cardId = result.insertId;

    // ✅ QR code generate pannunga
    if (includeQr) {
      // ✅ Public base URL use pannunga
      const base = "https://mallikaa851.github.io/card";
      const cardUrl = `${base}/card/${cardId}`;
      const qrDataUrl = await QRCode.toDataURL(cardUrl);
      const base64Data = qrDataUrl.replace(/^data:image\/png;base64,/, "");
      const qrFilename = `qr-${cardId}.png`;
      const qrPathOnDisk = path.join(__dirname, "public/uploads/qrs", qrFilename);
      fs.mkdirSync(path.dirname(qrPathOnDisk), { recursive: true });
      fs.writeFileSync(qrPathOnDisk, base64Data, 'base64');
      const qrPublicPath = `/uploads/qrs/${qrFilename}`;

      await new Promise((resolve, reject) => {
        conn.query("UPDATE cards SET qr_code = ? WHERE id = ?", [qrPublicPath, cardId], (err, r) => err ? reject(err) : resolve(r));
      });
    }

   res.redirect(`/preview?id=${cardId}&cardOnly1=true`);
    delete req.session.tempCard;
  } catch (err) {
    console.error("saveCardFromPreview error:", err);
    res.status(500).send("Server error saving card");
  }
});



app.post('/preview', upload.single('logo'), async (req, res) => {
  const { full_name, job_title, phone, email, address, website, license_no,  card_type, font_family, font_size, color_primary, color_secondary, color_text, social_facebook , social_instagram, social_linkedin, social_twitter, social_whatsapp, social_youtube } = req.body;

  if (!full_name || !card_type) {
    return res.status(400).send('Please fill the form correctly');
  }

  const logoFile = req.file ? req.file.filename : null;

  // QR opens the live card page with same data
  const base = `${req.protocol}://${req.get('host')}`;
  const cardUrl =
    `${base}/card?card_type=${encodeURIComponent(card_type)}` +
    `&full_name=${encodeURIComponent(full_name)}` +
    `&job_title=${encodeURIComponent(job_title)}` +
    `&phone=${encodeURIComponent(phone)}` +
    `&email=${encodeURIComponent(email)}` +
    
    `&website=${encodeURIComponent(website)}` +
    `&license_no=${encodeURIComponent(license_no)}`+
    `&font_family=${encodeURIComponent(font_family)}`+
    `&font_size=${encodeURIComponent(font_size)}`+
    `&color_primary=${encodeURIComponent(color_primary || '#ffffff')}` +
    `&color_secondary=${encodeURIComponent(color_secondary||'#0000ff')}`+
    `&color_text=${encodeURIComponent(color_text || '#000000')}` +
    (logoFile ? `&logo=${encodeURIComponent(logoFile)}` : '');

  const qrCodeDataURL = await QRCode.toDataURL(cardUrl);

  const userData = {
    full_name, job_title, phone, email, website, license_no,
    color_primary,color_secondary, color_text,
    card_type: Number(card_type),font_family, font_size,
    logo: logoFile,             
    qrCodeDataURL              
  };

  res.render('preview', { 
    userData,
    cardOnly: false,
    card_type,
    user: { username: req.session.username } 
 });
});

// QR scan/open target (renders the chosen card)

app.get('/card', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.redirect('/login');
    }

    // Example: DB la irundhu last saved card fetch panna
    const sql = "SELECT * FROM cards WHERE user_id = ? ORDER BY id DESC LIMIT 1";
    conn.query(sql, [req.session.userId], async (err, results) => {
      if (err || results.length === 0) {
        return res.send("No card data found");
      }

      const card = results[0];
      const cardType = Number(card.card_type || 1);

      // QR code generate panna
      const qrData = `${card.full_name} | ${card.phone} | ${card.email} | ${card.website}`;
      const qrCodeDataURL = await QRCode.toDataURL(qrData);

      const userData = {
        full_name: card.full_name,
        job_title: card.job_title,
        phone: card.phone,
        email: card.email,
        website: card.website,
        license_no: card.license_no,
        font_family: card.font_family,
        font_size: card.font_size,
        color_primary: card.color_primary || '#ffffff',
        color_secondary: card.color_secondary || '#0000ff',
        color_text: card.color_text || '#000000',
        logo: card.logo || null,
        qrCodeDataURL
      };

      res.render('preview', { userData, card_type: cardType });
    });
  } catch (err) {
    console.error("Error loading card:", err);
    res.send("Card preview error");
  }
});


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log(err);
        }
        res.clearCookie('connect.sid'); 
        res.redirect('/login');
    });
});

// Card display route

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});