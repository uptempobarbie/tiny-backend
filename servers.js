const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 5000;


mongoose.connect(process.env.MONGODB_URI);
                
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema and model
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  balance: { type: Number, default: 0 },
});
const User = mongoose.model('User', UserSchema);

// Middleware for JWT auth
const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashed });
  await user.save();
  res.json({ message: 'Registered successfully' });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
}); // ← This closing bracket was missing!

// Get balance
app.get('/api/balance', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json({ balance: user.balance });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
