const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'secretKey', resave: false, saveUninitialized: true }));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/cyberpunkAuth');

// User schema with role
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
});
const User = mongoose.model('User', UserSchema);

// Serve static files (your HTML/CSS)
app.use(express.static(__dirname));

// Register route
app.post('/submit_registration', async (req, res) => {
  const { username, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hashedPassword, role });
  res.redirect('/login.html');
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    req.session.role = user.role;
    res.redirect('/index.html');
  } else {
    res.send('Invalid credentials');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/index.html');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));