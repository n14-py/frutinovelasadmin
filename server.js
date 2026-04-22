/**
 * ============================================================================
 * FRUTINOVELAS - ENTERPRISE MASTER ENGINE v14.0 (ULTRA OPTIMIZADO)
 * ============================================================================
 * Autor: Frutinovelas Dev Team
 * Descripción: Servidor monolítico masivo para la gestión completa del Backend.
 * Incluye Sistema de Colas (Queue) avanzado para FFMPEG 1 a 1, Sistema 
 * Financiero de Doble Verificación (Estimado vs Aprobado), logs de auditoría,
 * y tareas cronométricas avanzadas.
 * ============================================================================
 */

require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const os = require('os');
const multer = require('multer');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegInstaller = require('@ffmpeg-installer/ffmpeg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const crypto = require('crypto');

// ============================================================================
// 1. CONFIGURACIÓN INICIAL, LOGS AVANZADOS Y AUDITORÍA
// ============================================================================
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
const app = express();

app.set('trust proxy', 1);

// Sistema de Logs Avanzado
class Logger {
    static getTimestamp() { return new Date().toISOString(); }
    static info(msg) { console.log(`\x1b[36m[INFO]\x1b[0m ${this.getTimestamp()} - ${msg}`); }
    static warn(msg) { console.warn(`\x1b[33m[WARN]\x1b[0m ${this.getTimestamp()} - ${msg}`); }
    static error(msg, err = '') { console.error(`\x1b[31m[ERROR]\x1b[0m ${this.getTimestamp()} - ${msg}`, err); }
    static success(msg) { console.log(`\x1b[32m[SUCCESS]\x1b[0m ${this.getTimestamp()} - ${msg}`); }
    static audit(userId, action, details) {
        console.log(`\x1b[35m[AUDIT]\x1b[0m ${this.getTimestamp()} - User:${userId} | Action:${action} | Details:${JSON.stringify(details)}`);
        // Opcional: Aquí podrías guardar esto en una base de datos de logs
    }
}

Logger.info("Iniciando secuencia de arranque: Fruti Engine v14.0 (Ultra Queue Edition)...");

// ============================================================================
// 2. SEGURIDAD, MIDDLEWARES Y RATE LIMITS ESPECÍFICOS
// ============================================================================
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false })); 
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// Limitadores de peticiones refinados
const globalLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 2000, 
    message: { error: "Demasiadas peticiones. Protección DDoS activada." } 
});
const authLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 20, 
    message: { error: "Demasiados intentos de login. Cuenta temporalmente bloqueada." } 
});
const uploadLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000, 
    max: 300, 
    message: { error: "Límite de subidas a la cola alcanzado." } 
});
const financeLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 50,
    message: { error: "Demasiadas operaciones financieras. Espere." }
});

app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/admin/finanzas/', financeLimiter);

// ============================================================================
// 3. CONEXIÓN A BASE DE DATOS (FIREBASE) CON REINTENTOS
// ============================================================================
let db;
let messaging;

const connectToFirebase = () => {
    try {
        const serviceAccount = require("./serviceAccountKey.json");
        if (!admin.apps.length) {
            admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        }
        db = admin.firestore();
        messaging = admin.messaging();
        
        // Optimización de Firestore
        db.settings({ ignoreUndefinedProperties: true });
        
        Logger.success("Conexión a Firebase Firestore y Cloud Messaging establecida con éxito.");
    } catch (e) {
        Logger.error("Fallo crítico al conectar con Firebase. Verifique serviceAccountKey.json", e.message);
        process.exit(1);
    }
};
connectToFirebase();

// ============================================================================
// 4. SISTEMA DE AUTORIZACIÓN Y ROLES AVANZADOS (JWT)
// ============================================================================
const JWT_SECRET = process.env.JWT_SECRET || 'frutinovelas_super_secret_master_key_2026_xYz_ULTRA';

const verificarToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        Logger.warn(`Intento de acceso denegado (Sin Token) desde IP: ${req.ip} a la ruta ${req.originalUrl}`);
        return res.status(403).json({ error: "Firma de seguridad ausente o formato incorrecto." });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; 
        
        // Verificación de baneo en tiempo real (evita que sigan usando la sesión si fueron baneados)
        if (req.user.role === 'creador') {
            const userDoc = await db.collection('creadores').doc(req.user.id).get();
            if (userDoc.exists && userDoc.data().estado === 'baneado') {
                return res.status(403).json({ error: "Su cuenta ha sido suspendida. Contacte a soporte." });
            }
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: "Sesión inválida o expirada. Por favor, vuelva a iniciar sesión." });
    }
};

const esAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        Logger.warn(`INTRUSIÓN BLOQUEADA: Usuario ${req.user.id} intentó acceder a ruta de Admin.`);
        return res.status(403).json({ error: "Acceso denegado. Se requieren privilegios de Super Administrador." });
    }
    next();
};

const esCreadorOAdmin = (req, res, next) => {
    if (req.user.role !== 'creador' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Acceso denegado. Se requiere cuenta de Creador de Contenido." });
    }
    next();
};

// ============================================================================
// 5. ENRUTAMIENTO FRONTEND (VISTAS ESTÁTICAS Y SPA)
// ============================================================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Rutas Públicas
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(publicPath, 'login.html')));

// Rutas Super Admin
const adminRoutes = ['admin', 'admin/usuarios', 'admin/creadores', 'admin/contenido', 'admin/finanzas', 'admin/marketing'];
adminRoutes.forEach(route => {
    app.get(`/${route}`, (req, res) => {
        const filePath = path.join(publicPath, `${route.replace('admin', 'admin/index').replace('/index', '')}.html`);
        if (fs.existsSync(filePath)) res.sendFile(filePath);
        else res.status(404).send("Vista administrativa no encontrada.");
    });
});

// Rutas Creador
const creatorRoutes = ['creador', 'creador/mis-series', 'creador/nueva-serie', 'creador/finanzas', 'creador/config', 'creador/editar-serie'];
creatorRoutes.forEach(route => {
    app.get(`/${route}`, (req, res) => {
        const filePath = path.join(publicPath, `${route.replace('creador', 'creador/index').replace('/index', '')}.html`);
        if (fs.existsSync(filePath)) res.sendFile(filePath);
        else res.status(404).send("Vista de creador no encontrada.");
    });
});

// ============================================================================
// 6. API REST: MÓDULO DE AUTENTICACIÓN AVANZADA
// ============================================================================
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: "Por favor envíe correo y contraseña completos." });
    }

    try {
        // 1. Verificación Super Admin
        if (email === 'admin' && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign({ id: 'admin', role: 'admin', nombre: 'Super Administrador' }, JWT_SECRET, { expiresIn: '72h' });
            Logger.audit('admin', 'LOGIN_SUCCESS', { ip: req.ip });
            return res.json({ success: true, token, role: 'admin', redirect: '/admin' });
        }

        // 2. Verificación Creador
        const snap = await db.collection('creadores').where('correo', '==', email).get();
        if (snap.empty) {
            Logger.audit('unknown', 'LOGIN_FAILED_NOT_FOUND', { email, ip: req.ip });
            return res.status(401).json({ error: "Credenciales incorrectas o usuario no encontrado." });
        }
        
        const userDoc = snap.docs[0];
        const user = userDoc.data();
        
        if (user.estado === 'baneado') {
            Logger.audit(userDoc.id, 'LOGIN_FAILED_BANNED', { ip: req.ip });
            return res.status(403).json({ error: "Tu cuenta ha sido baneada permanentemente por la administración." });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            Logger.audit(userDoc.id, 'LOGIN_FAILED_WRONG_PASS', { ip: req.ip });
            return res.status(401).json({ error: "Contraseña incorrecta." });
        }

        const token = jwt.sign({ id: userDoc.id, role: 'creador', nombre: user.nombre }, JWT_SECRET, { expiresIn: '24h' });
        
        await userDoc.ref.update({ 
            ultimoAcceso: admin.firestore.FieldValue.serverTimestamp(),
            ultimaIp: req.ip,
            loginCount: admin.firestore.FieldValue.increment(1)
        });

        Logger.audit(userDoc.id, 'LOGIN_SUCCESS', { ip: req.ip, userName: user.nombre });
        res.json({ success: true, token, role: 'creador', nombre: user.nombre, redirect: '/creador' });

    } catch (e) {
        Logger.error("Error crítico en módulo de login", e);
        res.status(500).json({ error: "Fallo interno en el servidor de autenticación." }); 
    }
});

// ============================================================================
// 7. API REST: MÓDULO SUPER ADMIN - ESTADÍSTICAS GLOBALES
// ============================================================================
app.get('/api/admin/stats', verificarToken, esAdmin, async (req, res) => {
    try {
        const [usersSnap, seriesSnap, creadoresSnap, transaccionesSnap] = await Promise.all([
            db.collection('users').get(),
            db.collection('novelas').get(),
            db.collection('creadores').get(),
            db.collection('transaccionesFinancieras').where('tipo', '==', 'pago_completado').get()
        ]);

        let ingresosEstimados = 0;
        let deudaAprobada = 0;
        let deudaPendienteRevision = 0;
        let seriesAprobadas = 0;
        let seriesPendientes = 0;
        let totalPagadoHistorico = 0;

        usersSnap.forEach(doc => {
            const u = doc.data();
            ingresosEstimados += ((u.coins || 0) * 0.01);
            if(u.planActivo && u.planActivo !== 'Gratis') ingresosEstimados += 5.99;
        });

        seriesSnap.forEach(doc => {
            const s = doc.data();
            if(s.estado === 'aprobado') seriesAprobadas++;
            if(s.estado === 'pendiente') seriesPendientes++;
        });

        creadoresSnap.forEach(doc => {
            const data = doc.data();
            deudaAprobada += (data.saldoPendiente || 0); // Lo que debes pagar ya verificado
            deudaPendienteRevision += (data.saldoEstimado || 0); // Lo que el sistema generó automático
        });

        transaccionesSnap.forEach(doc => {
            totalPagadoHistorico += (doc.data().monto || 0);
        });

        res.json({
            totalUsuarios: usersSnap.size,
            ingresosGlobales: ingresosEstimados,
            seriesAprobadas,
            seriesPendientes,
            totalCreadores: creadoresSnap.size,
            deudaAprobada,
            deudaPendienteRevision,
            totalPagadoHistorico
        });
    } catch (e) {
        Logger.error("Error calculando estadísticas", e);
        res.status(500).json({ error: "Error calculando métricas del sistema." });
    }
});

// ============================================================================
// 8. API REST: MÓDULO SUPER ADMIN - USUARIOS MÓVILES
// ============================================================================
app.get('/api/admin/usuarios-app', verificarToken, esAdmin, async (req, res) => {
    try {
        const snap = await db.collection('users').orderBy('createdAt', 'desc').limit(1000).get();
        res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/usuarios-app/:id/banear', verificarToken, esAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await admin.auth().updateUser(id, { disabled: true }); 
        await db.collection('users').doc(id).update({ 
            estado: 'baneado', 
            fechaBaneo: admin.firestore.FieldValue.serverTimestamp() 
        });
        Logger.audit('admin', 'BAN_APP_USER', { targetId: id });
        res.json({ success: true, mensaje: "Usuario baneado exitosamente." });
    } catch (e) { 
        Logger.error(`Error baneando usuario ${req.params.id}`, e);
        res.status(500).json({ error: e.message }); 
    }
});

app.post('/api/admin/usuarios-app/:id/regalo', verificarToken, esAdmin, async (req, res) => {
    const { tipo, cantidad } = req.body; 
    try {
        const userRef = db.collection('users').doc(req.params.id);
        if (tipo === 'monedas') {
            await userRef.update({ coins: admin.firestore.FieldValue.increment(Number(cantidad)) });
        } else if (tipo === 'vip_dias') {
            const newExpiry = new Date();
            newExpiry.setDate(newExpiry.getDate() + Number(cantidad));
            await userRef.update({ 
                vipExpiry: admin.firestore.Timestamp.fromDate(newExpiry),
                planActivo: 'VIP Soporte'
            });
        }
        Logger.audit('admin', 'GIFT_USER', { targetId: req.params.id, tipo, cantidad });
        res.json({ success: true, mensaje: `Regalo procesado correctamente.` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================================
// 9. API REST: MÓDULO SUPER ADMIN - SISTEMA FINANCIERO AVANZADO
// ============================================================================

app.get('/api/admin/creadores', verificarToken, esAdmin, async (req, res) => {
    try {
        const snap = await db.collection('creadores').orderBy('fechaRegistro', 'desc').get();
        res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/creadores', verificarToken, esAdmin, async (req, res) => {
    const { nombre, correo, password } = req.body;
    try {
        const existe = await db.collection('creadores').where('correo', '==', correo).get();
        if (!existe.empty) return res.status(400).json({ error: "El correo ya está registrado." });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const nuevoCreador = {
            nombre,
            correo,
            password: hashedPassword,
            estado: 'activo',
            strikes: 0,
            saldoPendiente: 0, // Saldo REAL a pagar (aprobado por admin)
            saldoEstimado: 0,  // Saldo automático generado por vistas
            gananciasTotalesPagadas: 0,
            fechaRegistro: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('creadores').add(nuevoCreador);
        Logger.audit('admin', 'CREATE_CREATOR', { newCreatorId: docRef.id });
        res.json({ success: true, id: docRef.id, mensaje: "Creador registrado exitosamente." });
    } catch (e) {
        res.status(500).json({ error: "Error al crear el creador." });
    }
});

app.put('/api/admin/creadores/:id/contrato', verificarToken, esAdmin, async (req, res) => {
    const { tipoPago, valorPago, estado } = req.body;
    try {
        await db.collection('creadores').doc(req.params.id).update({ 
            'contrato.tipo': tipoPago, 
            'contrato.valor': Number(valorPago), 
            estado: estado,
            actualizadoPor: req.user.id,
            fechaActualizacion: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true, mensaje: "Contrato del creador actualizado con éxito." });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

/**
 * NUEVO: VERIFICACIÓN Y APROBACIÓN DE SALDO
 * Este endpoint es el núcleo de tu solicitud: Permite revisar el saldo generado
 * automáticamente y transformarlo en Deuda Real luego de tu auditoría humana.
 */
app.post('/api/admin/finanzas/aprobar-saldo', verificarToken, esAdmin, async (req, res) => {
    const { creadorId, montoDescontarEstimado, montoAprobarReal, notaRevision } = req.body;
    
    if (montoDescontarEstimado < 0 || montoAprobarReal < 0) {
        return res.status(400).json({ error: "Los montos no pueden ser negativos." });
    }

    try {
        const creadorRef = db.collection('creadores').doc(creadorId);
        
        // Uso de Transacción para garantizar que no se duplique dinero si hay peticiones concurrentes
        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(creadorRef);
            if (!doc.exists) throw new Error("El creador no existe en la base de datos.");
            
            const data = doc.data();
            
            // Lógica de seguridad: No puede descontar más de lo estimado que existe
            const estimadoActual = data.saldoEstimado || 0;
            if (montoDescontarEstimado > estimadoActual) {
                throw new Error(`El creador solo tiene $${estimadoActual} en saldo estimado.`);
            }

            const nuevoEstimado = estimadoActual - Number(montoDescontarEstimado);
            const nuevoAprobado = (data.saldoPendiente || 0) + Number(montoAprobarReal);

            transaction.update(creadorRef, {
                saldoEstimado: nuevoEstimado,
                saldoPendiente: nuevoAprobado,
                ultimaRevisionAdmin: admin.firestore.FieldValue.serverTimestamp()
            });

            // Registro de Auditoría Financiera
            const logRef = db.collection('transaccionesFinancieras').doc();
            transaction.set(logRef, {
                creadorId: creadorId,
                tipo: 'aprobacion_saldo',
                montoEstimadoDescontado: Number(montoDescontarEstimado),
                montoRealAprobado: Number(montoAprobarReal),
                diferenciaPenalizada: Number(montoDescontarEstimado) - Number(montoAprobarReal),
                nota: notaRevision || 'Revisión periódica de sistema',
                adminId: req.user.id,
                fecha: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        Logger.audit('admin', 'FINANCE_APPROVAL', { creadorId, montoAprobarReal });
        res.json({ success: true, mensaje: "Saldo analizado y trasladado a Deuda Pendiente exitosamente." });

    } catch (e) {
        Logger.error("Error en aprobación financiera", e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/creadores/:id/pagar', verificarToken, esAdmin, async (req, res) => {
    const { monto, comprobanteId } = req.body;
    try {
        const creadorRef = db.collection('creadores').doc(req.params.id);
        
        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(creadorRef);
            const data = doc.data();
            
            if (monto > data.saldoPendiente) {
                throw new Error("El monto a pagar es mayor a la deuda pendiente aprobada.");
            }

            transaction.update(creadorRef, {
                saldoPendiente: admin.firestore.FieldValue.increment(-Number(monto)),
                gananciasTotalesPagadas: admin.firestore.FieldValue.increment(Number(monto))
            });

            const logRef = db.collection('transaccionesFinancieras').doc();
            transaction.set(logRef, {
                creadorId: req.params.id,
                tipo: 'pago_completado',
                monto: Number(monto),
                comprobante: comprobanteId || 'N/A',
                fecha: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, mensaje: "Pago registrado en el libro contable." });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

app.delete('/api/admin/creadores/:id', verificarToken, esAdmin, async (req, res) => {
    try {
        await db.collection('creadores').doc(req.params.id).delete();
        Logger.audit('admin', 'DELETE_CREATOR', { targetId: req.params.id });
        res.json({ success: true, mensaje: "Creador eliminado exitosamente." });
    } catch (e) { res.status(500).json({ error: "Fallo al eliminar el creador." }); }
});


// ============================================================================
// 10. API REST: MÓDULO SUPER ADMIN - MODERACIÓN DE SERIES Y CONTENIDO
// ============================================================================

app.get('/api/admin/novelas', verificarToken, esAdmin, async (req, res) => {
    try {
        const snap = await db.collection('novelas').orderBy('fechaCreacion', 'desc').get();
        res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/novelas/:id/estado', verificarToken, esAdmin, async (req, res) => {
    try {
        await db.collection('novelas').doc(req.params.id).update({ estado: req.body.estado });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/novelas/:id/destacar', verificarToken, esAdmin, async (req, res) => {
    try {
        const prev = await db.collection('novelas').where('esDestacada', '==', true).get();
        const batch = db.batch();
        prev.forEach(doc => batch.update(doc.ref, { esDestacada: false }));
        batch.update(db.collection('novelas').doc(req.params.id), { esDestacada: true });
        await batch.commit();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Borrado en Cascada Absoluto (Evita documentos fantasma)
app.delete('/api/admin/novelas/:id', verificarToken, esAdmin, async (req, res) => {
    try {
        const novelaRef = db.collection('novelas').doc(req.params.id);
        const episodiosSnap = await novelaRef.collection('episodios').get();
        
        const batch = db.batch();
        episodiosSnap.docs.forEach(doc => {
            batch.delete(doc.ref);
            // Idealmente aquí también deberíamos encolar un borrado en BunnyCDN de los videos físicos.
        });
        batch.delete(novelaRef);
        
        await batch.commit();
        Logger.success(`Borrado Absoluto Ejecutado en Serie ID: ${req.params.id}`);
        res.json({ success: true, mensaje: "Eliminado de la base de datos por completo." });
    } catch (e) { 
        Logger.error(`Fallo en Borrado Cascada (Serie: ${req.params.id})`, e);
        res.status(500).json({ error: "Fallo crítico al borrar en Firebase." }); 
    }
});

// ============================================================================
// 11. API REST: MÓDULO DE MARKETING (PUSH NOTIFICATIONS)
// ============================================================================

app.post('/api/admin/marketing/push', verificarToken, esAdmin, async (req, res) => {
    const { titulo, mensaje, imagenUrl } = req.body;
    try {
        const payload = {
            notification: { title: titulo, body: mensaje, ...(imagenUrl && { imageUrl: imagenUrl }) },
            topic: 'global_users' 
        };
        await messaging.send(payload);
        
        await db.collection('historialNotificaciones').add({
            titulo, mensaje, imagenUrl,
            enviadoPor: req.user.nombre,
            fecha: admin.firestore.FieldValue.serverTimestamp()
        });

        Logger.success(`Notificación Push Global enviada: ${titulo}`);
        res.json({ success: true, mensaje: "Push enviada a todos los dispositivos." });
    } catch (e) { res.status(500).json({ error: "Fallo al enviar notificación FCM." }); }
});


// Añadir en la SECCIÓN 12 de server.js
app.get('/api/creador/perfil', verificarToken, esCreadorOAdmin, async (req, res) => {
    try {
        const doc = await db.collection('creadores').doc(req.user.id).get();
        if(!doc.exists) return res.status(404).json({error: "No encontrado"});
        res.json(doc.data());
    } catch(e) { res.status(500).json({error: "Error al cargar perfil."}); }
});

// ============================================================================
// 12. API REST: MÓDULO CREADOR DE CONTENIDO (ESTRUCTURA)
// ============================================================================

app.get('/api/creador/mis-novelas', verificarToken, esCreadorOAdmin, async (req, res) => {
    try {
        const snap = await db.collection('novelas').where('creadorId', '==', req.user.id).orderBy('fechaCreacion', 'desc').get();
        res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Crear SOLO la estructura. Los episodios se procesan luego en la cola.
app.post('/api/creador/novelas-estructura', verificarToken, esCreadorOAdmin, async (req, res) => {
    const { titulo, descripcion, portadaUrl } = req.body;
    
    if (!titulo) return res.status(400).json({ error: "El título es obligatorio." });

    try {
        const novelaRef = await db.collection('novelas').add({
            title: titulo,            
            titulo: titulo,           
            descripcion: descripcion || '',
            portadaUrl: portadaUrl || '',
            creadorId: req.user.id,
            nombreCreador: req.user.nombre,
            estado: 'pendiente',      // Pendiente de aprobación del Super Admin
            likes: 0,                 
            vistasTotales: 0,
            ingresosGenerados: 0,
            fechaCreacion: admin.firestore.FieldValue.serverTimestamp()
        });
        
        Logger.info(`Creador ${req.user.nombre} creó la estructura de la serie: ${titulo}`);
        res.json({ success: true, id: novelaRef.id });
    } catch (e) { res.status(500).json({ error: "Fallo al crear la estructura de la serie." }); }
});


// ============================================================================
// 13. MOTOR FFMPEG: BACKGROUND QUEUE SYSTEM (EL CORAZÓN ASÍNCRONO)
// ============================================================================
// Este módulo procesa estrictamente 1 por 1 para evitar matar tu servidor de $7

const upload = multer({ dest: os.tmpdir() });

class VideoQueueManager {
    constructor() {
        this.queue = [];
        this.isProcessing = false;
        this.consecutiveErrors = 0;
    }

    addJob(job) {
        this.queue.push(job);
        Logger.info(`[QUEUE] Nuevo trabajo encolado. Tamaño de cola: ${this.queue.length}`);
        this.processNext();
    }

    async processNext() {
        if (this.isProcessing || this.queue.length === 0) return;
        
        this.isProcessing = true;
        const task = this.queue.shift(); // Saca el primero (FIFO)
        
        Logger.info(`\n🎬 [WORKER INICIADO] Procesando Episodio ${task.numeroEpisodio} de Serie ${task.serieId}`);

        try {
            // Actualizar estado a "procesando" en Firebase
            await db.collection('novelas').doc(task.serieId).collection('episodios').doc(task.episodioId).update({
                estadoProceso: 'procesando',
                fechaInicioProceso: admin.firestore.FieldValue.serverTimestamp()
            });

            const optVideoPath = path.join(os.tmpdir(), `opt_${Date.now()}_${task.safeName}.mp4`);
            const thumbnailPath = path.join(os.tmpdir(), `thumb_${Date.now()}.jpg`);

            // FASE 1: Renderizado FFMPEG
            Logger.info(`[WORKER] Fase 1/3: Renderizando video con FFMPEG...`);
            await new Promise((resolve, reject) => {
                ffmpeg(task.originalPath)
                    .videoCodec('libx264') 
                    .audioCodec('aac')
                    .outputOptions([
                        '-preset ultrafast', // Máxima velocidad para bajo CPU
                        '-crf 28', 
                        '-vf scale=-2:1080', 
                        '-movflags +faststart'
                    ])
                    .save(optVideoPath)
                    .on('end', resolve)
                    .on('error', reject);
            });

            // FASE 2: Extracción Miniatura
            Logger.info(`[WORKER] Fase 2/3: Extrayendo miniatura...`);
            await new Promise((resolve, reject) => {
                ffmpeg(optVideoPath)
                    .screenshots({ 
                        timestamps: [1], 
                        filename: path.basename(thumbnailPath), 
                        folder: os.tmpdir(), 
                        size: '1080x1920' 
                    })
                    .on('end', resolve)
                    .on('error', reject);
            });

            // FASE 3: Subida a BunnyCDN
            Logger.info(`[WORKER] Fase 3/3: Subiendo a CDN...`);
            const vidBuffer = fs.readFileSync(optVideoPath);
            const thumbBuffer = fs.readFileSync(thumbnailPath);

            const uploadBunny = async (buffer, type, name) => {
                const url = `https://ny.storage.bunnycdn.com/${process.env.BUNNY_STORAGE_NAME}/${type}/${name}`;
                const resp = await fetch(url, {
                    method: 'PUT',
                    headers: { 
                        'AccessKey': process.env.BUNNY_API_KEY, 
                        'Content-Type': type === 'videos' ? 'video/mp4' : 'image/jpeg' 
                    },
                    body: buffer
                });
                if (!resp.ok) throw new Error("Rechazado por BunnyCDN");
                return `https://${process.env.BUNNY_PULL_ZONE}/${type}/${name}`;
            };

            const uniqueId = crypto.randomBytes(6).toString('hex');
            const [videoUrl, thumbnailUrl] = await Promise.all([
                uploadBunny(vidBuffer, 'videos', `vid_${Date.now()}_${uniqueId}.mp4`),
                uploadBunny(thumbBuffer, 'images', `thumb_${Date.now()}_${uniqueId}.jpg`)
            ]);

            // FASE 4: Actualización en Base de Datos como COMPLETADO
            await db.collection('novelas').doc(task.serieId).collection('episodios').doc(task.episodioId).update({
                videoUrl: videoUrl,
                portadaEpiUrl: thumbnailUrl,
                estadoProceso: 'completado',
                fechaFinProceso: admin.firestore.FieldValue.serverTimestamp()
            });

            Logger.success(`[WORKER COMPLETADO] Episodio [${task.episodioId}] listo.`);
            this.consecutiveErrors = 0; // Resetear errores

            // FASE 5: Limpieza de Servidor
            fs.unlinkSync(task.originalPath);
            fs.unlinkSync(optVideoPath);
            fs.unlinkSync(thumbnailPath);

        } catch (error) {
            Logger.error(`[WORKER ERROR CRÍTICO] Episodio [${task.episodioId}] falló.`, error);
            this.consecutiveErrors++;
            
            await db.collection('novelas').doc(task.serieId).collection('episodios').doc(task.episodioId).update({
                estadoProceso: 'error', 
                errorDetalle: error.message
            });
            
            try { fs.unlinkSync(task.originalPath); } catch(e){} // Intento de limpieza de emergencia
            
            // Pausa de seguridad si el servidor se satura
            if(this.consecutiveErrors >= 3) {
                Logger.warn("Demasiados errores seguidos. El Worker dormirá 1 minuto.");
                await new Promise(res => setTimeout(res, 60000));
                this.consecutiveErrors = 0;
            }
        } finally {
            this.isProcessing = false;
            // Llamada recursiva al siguiente en cola
            this.processNext();
        }
    }
}

const QueueManager = new VideoQueueManager();

/**
 * @route   POST /api/media/queue-video
 * @desc    Recibe video, guarda en disco temporal, crea doc en BD y suelta al usuario al instante.
 */
app.post('/api/media/queue-video', uploadLimiter, verificarToken, esCreadorOAdmin, upload.single('video'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Archivo de video no recibido por el servidor." });
    
    const { serieId, numeroEpisodio, tituloEpisodio, precio } = req.body;
    if (!serieId || !numeroEpisodio) {
        fs.unlinkSync(req.file.path); // Limpiar si mandan mal los datos
        return res.status(400).json({ error: "Faltan datos obligatorios de la serie o el episodio." });
    }

    try {
        // 1. Crear documento preliminar en Firebase (Estado: en_cola)
        const epiRef = db.collection('novelas').doc(serieId).collection('episodios').doc();
        await epiRef.set({
            numero: Number(numeroEpisodio),
            tituloEpisodio: tituloEpisodio || `Episodio ${numeroEpisodio}`,
            descripcion: "Procesando contenido...",
            videoUrl: '', 
            precio: Number(precio) || 0,
            vistas: 0,
            estadoProceso: 'en_cola',
            fechaCarga: admin.firestore.FieldValue.serverTimestamp()
        });

        // 2. Enviar trabajo a la Cola en Memoria
        QueueManager.addJob({
            originalPath: req.file.path,
            safeName: req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_'),
            serieId: serieId,
            episodioId: epiRef.id,
            numeroEpisodio: numeroEpisodio
        });

        // 3. Devolver respuesta INSTANTÁNEA al frontend (El usuario ya puede cerrar la ventana)
        res.json({ 
            success: true, 
            episodioId: epiRef.id, 
            mensaje: "Video subido al servidor exitosamente. Ingresado a la cola de procesamiento en segundo plano." 
        });

    } catch (e) {
        Logger.error("Error al encolar el video", e);
        try { fs.unlinkSync(req.file.path); } catch(err){}
        res.status(500).json({ error: "Fallo crítico al encolar el video en el servidor." });
    }
});

/**
 * @route   GET /api/media/queue-status/:serieId/:episodioId
 * @desc    Ruta para que el Frontend consulte cómo va el procesamiento si se queda en la pestaña
 */
app.get('/api/media/queue-status/:serieId/:episodioId', verificarToken, async (req, res) => {
    try {
        const doc = await db.collection('novelas').doc(req.params.serieId).collection('episodios').doc(req.params.episodioId).get();
        if(!doc.exists) return res.status(404).json({ error: "Episodio no encontrado" });
        res.json({ estadoProceso: doc.data().estadoProceso || 'error' });
    } catch(e) {
        res.status(500).json({ error: "Error consultando estado." });
    }
});


app.post('/api/media/upload-image', verificarToken, multer({ storage: multer.memoryStorage() }).single('imagen'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No hay imagen." });
    try {
        const safeName = req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        const filename = `img_${Date.now()}_${safeName}`;
        const url = `https://ny.storage.bunnycdn.com/${process.env.BUNNY_STORAGE_NAME}/images/${filename}`;
        
        const response = await fetch(url, {
            method: 'PUT',
            headers: { 'AccessKey': process.env.BUNNY_API_KEY, 'Content-Type': req.file.mimetype },
            body: req.file.buffer
        });
        
        if (response.ok) {
            res.json({ imageUrl: `https://${process.env.BUNNY_PULL_ZONE}/images/${filename}` });
        } else {
            res.status(500).json({ error: "Bunny.net rechazó la imagen." });
        }
    } catch (e) { res.status(500).json({ error: "Fallo interno al subir imagen." }); }
});

// ============================================================================
// 14. TAREAS PROGRAMADAS AUTOMÁTICAS AVANZADAS (CRON JOBS)
// ============================================================================

// CRON 1: Limpieza diaria de usuarios VIP expirados (00:00 cada día)
cron.schedule('0 0 * * *', async () => {
    Logger.info("🌙 [CRON JOB] Iniciando revisión de Suscripciones VIP...");
    try {
        const now = admin.firestore.Timestamp.now();
        const expiredVips = await db.collection('users')
                                    .where('vipExpiry', '<', now)
                                    .where('planActivo', '!=', 'Gratis')
                                    .get();
        
        if (!expiredVips.empty) {
            const batch = db.batch();
            expiredVips.forEach(doc => {
                batch.update(doc.ref, { planActivo: 'Gratis', vipExpiry: null });
            });
            await batch.commit();
            Logger.success(`[CRON] ${expiredVips.size} cuentas VIP expiradas fueron pasadas a Gratis.`);
        }
    } catch (e) { Logger.error("[CRON ERROR] Fallo al limpiar VIPs", e); }
});

// CRON 2: Simulador de Ingresos Creadores (Estimador Automático) - Corre cada 48 Horas
// Este script simula buscar las vistas de las últimas 48hs y sumar al "Saldo Estimado"
cron.schedule('0 0 */2 * *', async () => {
    Logger.info("💰 [CRON JOB] Ejecutando cálculo de ingresos ESTIMADOS (Ciclo 48hs)...");
    try {
        const creadoresSnap = await db.collection('creadores').where('estado', '==', 'activo').get();
        const batch = db.batch();
        let actualizados = 0;

        // Aquí, en producción real, harías un query a una colección de "Vistas" de las últimas 48hs.
        // Para este motor, incrementamos de forma programática basada en su RPM o vistas totales de sus series.
        // Simularemos un incremento fijo por cuestiones de demostración del sistema.
        
        creadoresSnap.forEach(doc => {
            // Ejemplo: si el sistema detecta vistas, incrementa saldoEstimado
            // batch.update(doc.ref, { saldoEstimado: admin.firestore.FieldValue.increment(1.50) });
            // actualizados++;
        });

        if (actualizados > 0) {
            await batch.commit();
            Logger.success(`[CRON FINANZAS] Ingresos estimados actualizados para ${actualizados} creadores.`);
        }
    } catch (e) { Logger.error("[CRON ERROR] Fallo Finanzas Estimadas", e); }
});

// CRON 3: Limpiador de Cola Atascada (Corre cada hora)
// Si por alguna razón el servidor se reinicia y quedaron videos "en_cola" o "procesando", los marca como error.
cron.schedule('0 * * * *', async () => {
    try {
        const series = await db.collection('novelas').get();
        const batch = db.batch();
        let fixed = 0;
        
        for (let serieDoc of series.docs) {
            const episodios = await serieDoc.ref.collection('episodios')
                .where('estadoProceso', 'in', ['en_cola', 'procesando'])
                .get();
                
            episodios.forEach(epiDoc => {
                // Si lleva horas en ese estado, fue un fallo del servidor
                batch.update(epiDoc.ref, { estadoProceso: 'error', errorDetalle: 'Interrupción del servidor' });
                fixed++;
            });
        }
        if(fixed > 0) {
            await batch.commit();
            Logger.warn(`[CRON WATCHDOG] Se marcaron ${fixed} episodios atascados como error.`);
        }
    } catch(e) {}
});


// Global Error Handler Final
app.use((err, req, res, next) => {
    Logger.error(`Error crítico no capturado en ruta ${req.path}`, err);
    res.status(500).json({ error: "Se ha producido un error interno masivo en el servidor." });
});

// ============================================================================
// 15. ARRANQUE DEL SERVIDOR EMPRESARIAL
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n=================================================================`);
    console.log(`🚀 FRUTI ENGINE SUPER ADMIN 14.0 [ULTRA ASYNC QUEUE EDITION]`);
    console.log(`=================================================================`);
    console.log(`🛡️  Módulos ACTIVOS: Helmet, Cors, JWT, Rate Limiting x4`);
    console.log(`🎥 Motor Multimedia: COLA FFMPEG 1x1 [Modo Background Seguro]`);
    console.log(`💰 Motor Financiero: DOBLE AUDITORÍA (Estimado -> Real)`);
    console.log(`⏰ Tareas Cron: VIP (Diario), Finanzas (48hs), Watchdog (Hora)`);
    console.log(`🌐 Escuchando tráfico global en puerto: ${PORT}`);
    console.log(`=================================================================\n`);
});