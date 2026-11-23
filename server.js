require('dotenv').config();

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

// Llave secreta para firmar los JWT
const SECRET_KEY = process.env.JWT_SECRET || 'clave_secreta_para_clase_seguridad';

// Conexión a la BD en Docker
const pool = new Pool({
    user: process.env.DB_USER || 'admin',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'netsentinel',
    password: process.env.DB_PASSWORD || 'adminpassword',
    port: Number(process.env.DB_PORT) || 5432,
});

// 1. WAF Middleware Avanzado: Motor de Detección Profunda ajustado
const wafMiddleware = async (req, res, next) => {
    try {
        // Limpiamos los caracteres de formato JSON nativo (", {, }) para evitar Falsos Positivos
        const bodyString = JSON.stringify(req.body || {}).replace(/["{}]/g, ''); 
        const payload = decodeURIComponent(req.originalUrl) + bodyString;
        
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'] || ''; 

        // Firmas ajustadas: Quitamos el chequeo de comillas sueltas que rompían el Login normal
        const sqliPattern = /(OR\s+\d+=\d+)|(UNION\s+SELECT)|(--)|(';)/i;
        const pathTraversalPattern = /(\.\.\/)|(\/etc\/[a-z]+)|(c:\\windows)/i;
        const xssPattern = /(<script>)|(javascript:)|(onerror=)|(onload=)/i;
        const cmdInjectionPattern = /(;\s*cat)|(\|\s*ls)|(;\s*rm)|(`.*`)|(\$\(.*\))/i;
        const botPattern = /(sqlmap)|(nmap)|(nikto)|(dirb)/i;

        let detectedAttack = null;
        let severity = 'CRITICAL';
        let description = '';

        if (sqliPattern.test(payload)) {
            detectedAttack = 'SQL Injection (SQLi)';
            description = 'Intento de manipulación de la base de datos detectado en el payload.';
        } else if (pathTraversalPattern.test(payload)) {
            detectedAttack = 'Path Traversal / LFI';
            severity = 'HIGH';
            description = 'Se bloqueó un intento de escalar directorios para leer archivos del servidor.';
        } else if (xssPattern.test(payload)) {
            detectedAttack = 'Cross-Site Scripting (XSS)';
            severity = 'MEDIUM';
            description = 'Ejecución de código JavaScript bloqueada por políticas del WAF.';
        } else if (cmdInjectionPattern.test(payload)) {
            detectedAttack = 'OS Command Injection';
            description = 'Alerta Máxima: Intento de ejecución de comandos remotos (RCE) en el servidor.';
        } else if (botPattern.test(userAgent)) {
            detectedAttack = 'Automated Scanner Bot';
            severity = 'HIGH';
            description = 'Tráfico bloqueado originado por una herramienta de escaneo de vulnerabilidades.';
        }

        if (detectedAttack) {
            await pool.query(
                'INSERT INTO alerts (severity, source_ip, event_type, description) VALUES ($1, $2, $3, $4)',
                [severity, clientIp, detectedAttack, description]
            );
            return res.status(403).json({ error: `Bloqueado por NetSentinel WAF: ${detectedAttack}` });
        }

        next();
    } catch (err) {
        console.error("Error en WAF:", err);
        next();
    }
};

app.use(wafMiddleware); // Activa el detector de ataques para todas las rutas

// 2. Rate Limit Inteligente: El backend genera la alerta al bloquear
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Ventana de 15 minutos
    max: 5, // Bloquea tras 5 intentos
    handler: async (req, res) => {
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        // El backend detecta la fuerza bruta y guarda la alerta solo
        await pool.query(
            'INSERT INTO alerts (severity, source_ip, event_type, description) VALUES ($1, $2, $3, $4)',
            ['HIGH', clientIp, 'Brute Force Login', 'Múltiples intentos fallidos. Rate Limit (429) activado por el servidor.']
        );
        
        res.status(429).json({ error: 'Demasiados intentos. Bloqueo temporal.' });
    }
});

// Middleware de Seguridad: Validar JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acceso denegado.' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido.' });
        req.user = decoded;
        next();
    });
};

// --- ENDPOINTS ---

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username || 'unknown', clientIp, 'FAILED']);
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username, clientIp, 'FAILED']);
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        
        await pool.query('INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)', [username, clientIp, 'SUCCESS']);
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, message: 'Autenticación exitosa', role: user.role });

    } catch (error) {
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener Alertas WAF
app.get('/api/alerts', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alerts ORDER BY detected_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Error al recuperar telemetría' });
    }
});

// 3. Obtener Auditoría de Accesos (Protegido por JWT)
app.get('/api/audit', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM audit_logs ORDER BY id DESC');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al recuperar registros de auditoría' });
    }
});

// Limpiar alertas y auditoría para reiniciar una demo.
app.delete('/api/telemetry/reset', verifyToken, async (req, res) => {
    try {
        await pool.query('TRUNCATE TABLE alerts, audit_logs RESTART IDENTITY;');
        res.sendStatus(200);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al limpiar la telemetría' });
    }
});

const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, () => {
    console.log(`API de Seguridad corriendo en http://localhost:${PORT}`);
});
