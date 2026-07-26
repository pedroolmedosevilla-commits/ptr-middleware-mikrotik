/**
 * ============================================================================
 * CONECTA T - BACKEND CENTRAL DE GOBERNANZA (V2.4 - RUTAS ALINEADAS)
 * ============================================================================
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { RouterOSAPI } = require('node-routeros');
const snmp = require('net-snmp');

const app = express();
app.use(express.json());
app.use(cors());

// --- 1. INICIALIZACIÓN DE FIREBASE ADMIN (BÚNKER DE SEGURIDAD) ---
let db; 

try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        db = admin.firestore(); 
        console.log("✅ Firebase Admin SDK vinculado correctamente.");
    } else {
        console.warn("⚠️ Advertencia: FIREBASE_SERVICE_ACCOUNT no detectada. Modo Red únicamente.");
    }
} catch (e) {
    console.error("❌ Error crítico en Firebase Admin:", e.message);
}

// --- 2. MOTOR DE CONEXIÓN MIKROTIK ---
const conectarMikroTik = (ipRouter) => {
    const partes = ipRouter.split(':');
    const host = partes[0];
    const puerto = partes[1] ? parseInt(partes[1], 10) : (parseInt(process.env.MIKROTIK_PORT, 10) || 8728);

    return new RouterOSAPI({
        host: host,
        user: process.env.MIKROTIK_USER,
        password: process.env.MIKROTIK_PASSWORD,
        port: puerto,
        timeout: 10
    });
};

// ============================================================================
// 3. RUTAS OPERATIVAS (ALINEADAS CON FRONTEND TITÁN)
// ============================================================================

app.get('/', (req, res) => res.send('Servidor CONECTA T: Operativo y Blindado.'));

// 🚀 RUTA 1: REACTIVAR SERVICIO
app.post('/api/mikrotik/reactivar', async (req, res) => {
    const { ipCliente, ipRouter } = req.body;
    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        const registros = await conn.write('/ip/firewall/address-list/print', [`?address=${ipCliente}`, `?list=MOROSOS`]);
        if (registros.length > 0) {
            await conn.write('/ip/firewall/address-list/remove', [`=.id=${registros[0]['.id']}`]);
        }
        conn.close();
        res.json({ estatus: 'exito', mensaje: 'Internet restaurado' });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: error.message });
    }
});

// 🚀 RUTA 2: SUSPENDER SERVICIO (¡NUEVO!)
app.post('/api/mikrotik/suspender', async (req, res) => {
    const { ipCliente, ipRouter, comentario } = req.body;
    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        await conn.write('/ip/firewall/address-list/add', [
            `=address=${ipCliente}`, 
            `=list=MOROSOS`,
            `=comment=${comentario || 'Suspendido por App Titán'}`
        ]);
        conn.close();
        res.json({ estatus: 'exito', mensaje: 'Servicio suspendido con éxito' });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: error.message });
    }
});

// 🚀 RUTA 3: TELEMETRÍA (CORREGIDA LA RUTA A /api/mikrotik/status)
app.post('/api/mikrotik/status', async (req, res) => {
    const { ipRouter, puertoWan = 'ether1' } = req.body;
    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        const recursos = await conn.write('/system/resource/print');
        
        let temperaturaReal = 0;
        try {
            const salud = await conn.write('/system/health/print');
            if (salud && salud.length > 0) {
                const sensor = salud.find(s => s.name && s.name.includes('temperature'));
                temperaturaReal = sensor ? parseFloat(sensor.value) : (salud[0].temperature || 0);
            }
        } catch (e) {}

        let rxMbps = 0;
        try {
            const traffic = await conn.write('/interface/monitor-traffic', [`=interface=${puertoWan}`, '=once=']);
            if (traffic && traffic.length > 0) {
                rxMbps = (parseFloat(traffic[0]['rx-bits-per-second']) / 1000000).toFixed(1);
            }
        } catch (e) {}

        conn.close();
        res.json({
            estatus: 'exito',
            data: {
                cpu: recursos[0]['cpu-load'] || 0,
                ram: ((parseInt(recursos[0]['total-memory']) - parseInt(recursos[0]['free-memory'])) / parseInt(recursos[0]['total-memory']) * 100).toFixed(1),
                temp: temperaturaReal,
                rx: rxMbps,
                activos: 0 
            }
        });
    } catch (error) {
        if(conn) conn.close();
        res.json({ estatus: 'error', mensaje: 'Router Offline' });
    }
});

// ============================================================================
// 4. RUTAS DE SEGURIDAD
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
    const { pin } = req.body;
    if (!db) return res.status(503).json({ estatus: 'error', mensaje: 'Servicio de Matriz no disponible temporalmente' });

    try {
        const rolesRef = db.doc("artifacts/conecta-t-ecosistema/public/data/Configuracion/RolesAccesos");
        const docSnap = await rolesRef.get();
        const roles = docSnap.data();
        const usuario = roles[pin];

        if (usuario) {
            await db.collection("artifacts/conecta-t-ecosistema/public/data/AuditoriaAccesos").add({
                usuario: usuario.nombre,
                rol: usuario.rol,
                fecha: new Date().toLocaleString(),
                ip: req.ip,
                dispositivo: req.headers['user-agent']
            });

            res.json({ 
                estatus: 'exito', 
                perfil: { nombre: usuario.nombre, rol: usuario.rol, sector: usuario.sector || 'Todos' } 
            });
        } else {
            res.status(401).json({ estatus: 'error', mensaje: 'PIN Incorrecto' });
        }
    } catch (error) {
        res.status(500).json({ estatus: 'error', mensaje: 'Error de conexión con La Matriz' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 BACKEND CONECTA T V2.4 LISTO EN PUERTO ${PORT}`);
});