// api/index.js - Backend para Vercel Serverless
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Conexión a MongoDB (se cachea automáticamente)
let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }

  const connection = await mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  cachedDb = connection;
  return connection;
}

// Modelos
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const predictionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  matches: { type: Object, default: {} },
  playoffMatches: { type: Object, default: {} },
  topScorer: { type: String, default: '' },
  bestPlayer: { type: String, default: '' },
  submittedAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const resultsSchema = new mongoose.Schema({
  matches: { type: Object, default: {} },
  playoffMatches: { type: Object, default: {} },
  groupStandings: { type: Object, default: {} },
  topScorer: { type: String, default: '' },
  bestPlayer: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Prediction = mongoose.models.Prediction || mongoose.model('Prediction', predictionSchema);
const Results = mongoose.models.Results || mongoose.model('Results', resultsSchema);

// Middleware de autenticación
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error();
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Por favor autentícate' });
  }
};

// Middleware para admin
const adminAuth = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  next();
};

// ==================== RUTAS ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'API funcionando correctamente' });
});

// Registro
app.post('/api/register', async (req, res) => {
  try {
    await connectToDatabase();
    
    const { username, password, name } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const userCount = await User.countDocuments();
    const isAdmin = userCount === 0;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashedPassword,
      name,
      isAdmin
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        isAdmin: user.isAdmin
      },
      token
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    await connectToDatabase();
    
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        isAdmin: user.isAdmin
      },
      token
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Obtener usuario actual
app.get('/api/me', auth, async (req, res) => {
  await connectToDatabase();
  res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      name: req.user.name,
      isAdmin: req.user.isAdmin
    }
  });
});

// Guardar predicciones
app.post('/api/predictions', auth, async (req, res) => {
  try {
    await connectToDatabase();
    
    const { matches, playoffMatches, topScorer, bestPlayer } = req.body;

    let prediction = await Prediction.findOne({ userId: req.user._id });

    if (prediction) {
      prediction.matches = matches;
      prediction.playoffMatches = playoffMatches;
      prediction.topScorer = topScorer;
      prediction.bestPlayer = bestPlayer;
      prediction.updatedAt = new Date();
      await prediction.save();
    } else {
      prediction = new Prediction({
        userId: req.user._id,
        matches,
        playoffMatches,
        topScorer,
        bestPlayer
      });
      await prediction.save();
    }

    res.json({ message: 'Predicciones guardadas correctamente', prediction });
  } catch (error) {
    console.error('Error guardando predicciones:', error);
    res.status(500).json({ error: 'Error al guardar predicciones' });
  }
});

// Obtener predicciones del usuario actual
app.get('/api/predictions/me', auth, async (req, res) => {
  try {
    await connectToDatabase();
    const prediction = await Prediction.findOne({ userId: req.user._id });
    res.json({ prediction });
  } catch (error) {
    console.error('Error obteniendo predicciones:', error);
    res.status(500).json({ error: 'Error al obtener predicciones' });
  }
});

// Obtener todos los usuarios (solo admin)
app.get('/api/users', auth, adminAuth, async (req, res) => {
  try {
    await connectToDatabase();
    const users = await User.find().select('-password').lean();
    res.json({ users });
  } catch (error) {
    console.error('Error obteniendo usuarios:', error);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Obtener todas las predicciones (solo admin)
app.get('/api/predictions/all', auth, adminAuth, async (req, res) => {
  try {
    await connectToDatabase();
    const predictions = await Prediction.find().populate('userId', 'username name').lean();
    
    const predictionsMap = {};
    predictions.forEach(pred => {
      predictionsMap[pred.userId._id] = {
        ...pred,
        submittedAt: pred.submittedAt
      };
    });

    res.json({ predictions: predictionsMap });
  } catch (error) {
    console.error('Error obteniendo todas las predicciones:', error);
    res.status(500).json({ error: 'Error al obtener predicciones' });
  }
});

// Obtener predicción de un usuario específico (solo admin)
app.get('/api/predictions/user/:userId', auth, adminAuth, async (req, res) => {
  try {
    await connectToDatabase();
    const prediction = await Prediction.findOne({ userId: req.params.userId });
    res.json({ prediction });
  } catch (error) {
    console.error('Error obteniendo predicción del usuario:', error);
    res.status(500).json({ error: 'Error al obtener predicción' });
  }
});

// Guardar resultados (solo admin)
app.post('/api/results', auth, adminAuth, async (req, res) => {
  try {
    await connectToDatabase();
    
    const { matches, playoffMatches, groupStandings, topScorer, bestPlayer } = req.body;

    let results = await Results.findOne();

    if (results) {
      results.matches = matches;
      results.playoffMatches = playoffMatches;
      results.groupStandings = groupStandings;
      results.topScorer = topScorer;
      results.bestPlayer = bestPlayer;
      results.updatedAt = new Date();
      await results.save();
    } else {
      results = new Results({
        matches,
        playoffMatches,
        groupStandings,
        topScorer,
        bestPlayer
      });
      await results.save();
    }

    res.json({ message: 'Resultados guardados correctamente', results });
  } catch (error) {
    console.error('Error guardando resultados:', error);
    res.status(500).json({ error: 'Error al guardar resultados' });
  }
});

// Obtener resultados
app.get('/api/results', auth, async (req, res) => {
  try {
    await connectToDatabase();
    const results = await Results.findOne();
    res.json({ results: results || {} });
  } catch (error) {
    console.error('Error obteniendo resultados:', error);
    res.status(500).json({ error: 'Error al obtener resultados' });
  }
});

// Export para Vercel
module.exports = app;
