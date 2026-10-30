const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet()); // Inyecta cabeceras de seguridad HTTP instantáneamente

// Llave secreta para firmar los JWT (En producción esto va en un archivo .env)
const SECRET_KEY = 'clave_secreta_para_clase_seguridad';

// Conexión a la BD en Docker
const pool = new Pool({
    user: 'admin',
    host: 'localhost',
    database: 'netsentinel',
    password: 'adminpassword',
    port: 5432,
});

// Configuración de Rate Limit (Previene ataques de fuerza bruta al Login)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Ventana de 15 minutos
    max: 5, // Bloquea tras 5 intentos fallidos o exitosos
    message: { error: 'Demasiados intentos de acceso desde esta IP. Bloqueo temporal de 15 minutos.' }
});

// Middleware de Seguridad: Validar JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acceso denegado. Token no proporcionado.' });

    const token = authHeader.split(' ')[1]; // Formato esperado: "Bearer <token>"
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido o expirado.' });
        req.user = decoded; // Guardamos los datos del usuario en la request
        next();
    });
};

// Endpoint 1: Login (Con Rate Limiting, consultas parametrizadas y validación bcrypt)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        // Prevención de enumeración de usuarios
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const user = result.rows[0];
        
        // Validación de seguridad real contra el hash almacenado
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
        
        // Generamos el token incluyendo el rol (RBAC básico)
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, message: 'Autenticación exitosa', role: user.role });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint 2: Obtener Alertas (Protegido por JWT)
app.get('/api/alerts', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alerts ORDER BY detected_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al recuperar la telemetría' });
    }
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`API de Seguridad corriendo en http://localhost:${PORT}`);
});