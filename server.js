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
const allowedOrigins = (process.env.CORS_ORIGIN || 'https://seguridad-inform-tica-proyecto-fron.vercel.app,http://localhost:3000')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
app.use(cors({ origin: allowedOrigins }));
app.use(helmet()); // Inyecta cabeceras de seguridad HTTP instantáneamente

// Llave secreta para firmar los JWT
const SECRET_KEY = process.env.JWT_SECRET;

// Conexión a la BD en Docker
const pool = new Pool({
    ...(process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL }
        : {
            user: process.env.DB_USER || 'admin',
            host: process.env.DB_HOST || 'localhost',
            database: process.env.DB_NAME || 'netsentinel',
            password: process.env.DB_PASSWORD || 'adminpassword',
            port: Number(process.env.DB_PORT) || 5432,
        }),
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    connectionTimeoutMillis: Number(process.env.DB_CONNECTION_TIMEOUT_MS) || 10000,
});

app.set('trust proxy', 1);
pool.on('error', (error) => console.error('Error inesperado en PostgreSQL:', error));
const wafEnabled = process.env.WAF_ENABLED !== 'false';

const auditLogin = async (username, ipAddress, status) => {
    try {
        await pool.query(
            'INSERT INTO audit_logs (username, ip_address, status) VALUES ($1, $2, $3)',
            [username || 'unknown', ipAddress, status]
        );
    } catch (error) {
        console.error('No se pudo guardar el registro de auditoria:', error);
    }
};

// 1. WAF Middleware Avanzado: Motor de Detección Profunda ajustado
const wafMiddleware = async (req, res, next) => {
    if (!wafEnabled) return next();
    try {
        // Limpiamos los caracteres de formato JSON nativo (", {, }) para evitar Falsos Positivos
        const bodyString = JSON.stringify(req.body || {}).replace(/["{}]/g, ''); 
        const payload = decodeURIComponent(req.originalUrl) + bodyString;
        
        const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
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
            try {
                await pool.query(
                    'INSERT INTO alerts (severity, source_ip, event_type, description) VALUES ($1, $2, $3, $4)',
                    [severity, clientIp, detectedAttack, description]
                );
            } catch (error) {
                console.error('No se pudo guardar la alerta WAF:', error);
            }
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
    windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    limit: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { error: 'Demasiados intentos fallidos. Espera antes de volver a intentarlo.', code: 'RATE_LIMITED' },
});

// Middleware de Seguridad: Validar JWT
const verifyToken = (req, res, next) => {
    if (!SECRET_KEY) return res.status(503).json({ error: 'El servidor no tiene configurada JWT_SECRET.' });
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
    const { username, password } = req.body || {};
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
        return res.status(400).json({ error: 'Escribe un usuario y una contrasena validos.', code: 'INVALID_INPUT' });
    }
    if (!SECRET_KEY) {
        console.error('Falta JWT_SECRET en la configuracion del backend.');
        return res.status(503).json({ error: 'El servicio de autenticacion no esta configurado. Contacta al administrador.', code: 'AUTH_NOT_CONFIGURED' });
    }

    try {
        const result = await pool.query('SELECT id, username, password_hash, role FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            await auditLogin(username, clientIp, 'FAILED');
            return res.status(401).json({ error: 'Usuario o contrasena incorrectos.', code: 'INVALID_CREDENTIALS' });
        }

        const user = result.rows[0];
        if (typeof user.password_hash !== 'string' || !user.password_hash) {
            console.error('La cuenta no tiene un password_hash valido en users.');
            return res.status(503).json({ error: 'La cuenta no tiene una contrasena configurada correctamente. Contacta al administrador.', code: 'INVALID_ACCOUNT_SETUP' });
        }

        let validPassword;
        try {
            validPassword = await bcrypt.compare(password, user.password_hash);
        } catch (error) {
            console.error('No se pudo validar password_hash con bcryptjs:', error);
            return res.status(503).json({ error: 'La contrasena almacenada para esta cuenta no es valida. Contacta al administrador.', code: 'INVALID_PASSWORD_HASH' });
        }

        if (!validPassword) {
            await auditLogin(username, clientIp, 'FAILED');
            return res.status(401).json({ error: 'Usuario o contrasena incorrectos.', code: 'INVALID_CREDENTIALS' });
        }

        let token;
        try {
            token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        } catch (error) {
            console.error('No se pudo firmar el JWT:', error);
            return res.status(503).json({ error: 'No se pudo configurar la sesion. Contacta al administrador.', code: 'JWT_SIGNING_FAILED' });
        }

        await auditLogin(username, clientIp, 'SUCCESS');
        return res.json({ token, message: 'Autenticacion exitosa', role: user.role });
    } catch (error) {
        console.error('Error al autenticar contra PostgreSQL:', error);
        if (error.code === '42P01' || error.code === '42703') {
            return res.status(503).json({ error: 'El esquema de la base de datos esta incompleto. Ejecuta la migracion de NetSentinel en Neon.', code: 'DATABASE_SCHEMA_MISSING' });
        }
        if (['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET', '28P01', '3D000', '08000', '08006'].includes(error.code)) {
            return res.status(503).json({ error: 'No se pudo conectar a PostgreSQL. Revisa las credenciales, el host, el puerto y SSL del backend.', code: 'DATABASE_UNAVAILABLE' });
        }
        return res.status(500).json({ error: 'Error interno al iniciar sesion. Revisa los logs del backend.', code: 'LOGIN_FAILED' });
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
