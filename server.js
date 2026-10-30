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

// Endpoint 1: Login con Trazabilidad (Audit Logs), Rate Limiting y bcrypt
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            // Registro de auditoría: Intento fallido (usuario no existe)
            await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username || 'unknown', clientIp, 'FAILED']);
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const user = result.rows[0];
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            // Registro de auditoría: Intento fallido (contraseña incorrecta)
            await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username, clientIp, 'FAILED']);
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
        
        // Registro de auditoría: Acceso exitoso
        await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username, clientIp, 'SUCCESS']);
        
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

// Endpoint 3: Ingesta Dinámica de Alertas (Recibe telemetría de agentes externos)
app.post('/api/alerts', async (req, res) => {
    const { severity, source_ip, event_type, description } = req.body;

    // Validación estricta de la estructura de datos entrante
    if (!severity || !source_ip || !event_type || !description) {
        return res.status(400).json({ error: 'Payload incompleto. Faltan métricas de seguridad obligatorias.' });
    }

    try {
        const query = `
            INSERT INTO alerts (severity, source_ip, event_type, description) 
            VALUES ($1, $2, $3, $4) RETURNING *;
        `;
        const values = [severity, source_ip, event_type, description];
        
        const result = await pool.query(query, values);
        res.status(201).json({ message: 'Incidente de seguridad registrado exitosamente', alert: result.rows[0] });
    } catch (error) {
        console.error('Error procesando la telemetría:', error);
        res.status(500).json({ error: 'Error interno del SIEM al registrar el evento' });
    }
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`API de Seguridad corriendo en http://localhost:${PORT}`);
});