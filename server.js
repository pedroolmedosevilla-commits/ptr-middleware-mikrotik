/**
 * ============================================================================
 * CONECTA T - BACKEND CENTRAL DE GOBERNANZA (V2.2 - PRODUCCIÓN)
 * ============================================================================
 * Servidor seguro con compatibilidad para apps legacy y nuevas.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { RouterOSAPI } = require('node-routeros');
const snmp = require('net-snmp');

// --- 1. INICIALIZACIÓN DE FIREBASE ADMIN (BÚNKER DE SEGURIDAD) ---
try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("✅ Firebase Admin SDK vinculado correctamente.");
} catch (e) {
    console.error("❌ Error crítico: No se pudo inicializar Firebase Admin.", e.message);
}

const db = admin.firestore();
const app = express();
app.use(express.json());
app.use(cors());

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
// 3. RUTAS DE COMPATIBILIDAD (Para no romper tus apps actuales)
// ============================================================================

app.get('/', (req, res) => res.send('Servidor CONECTA T: Operativo y Blindado.'));

// Reactivación (La que usa tu App Mostrador y NOC actual)
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

// Telemetría (La que pide el Dashboard cada 3 segundos)
app.post('/api/mikrotik/status', async (req, res) => {
    const { ipRouter } = req.body;
    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        const recursos = await conn.write('/system/resource/print');
        conn.close();
        res.json({
            estatus: 'exito',
            data: {
                cpu: recursos[0]['cpu-load'],
                ram: ((parseInt(recursos[0]['total-memory']) - parseInt(recursos[0]['free-memory'])) / parseInt(recursos[0]['total-memory']) * 100).toFixed(1),
                activos: 0 
            }
        });
    } catch (error) {
        if(conn) conn.close();
        res.json({ estatus: 'error', mensaje: 'Router Offline' });
    }
});

// ============================================================================
// 4. NUEVAS RUTAS DE SEGURIDAD (Para las apps que vamos a actualizar)
// ============================================================================

// Login Blindado: Valida el PIN sin exponer la base de datos
app.post('/api/auth/login', async (req, res) => {
    const { pin } = req.body;
    try {
        const rolesRef = db.doc("artifacts/conecta-t-ecosistema/public/data/Configuracion/RolesAccesos");
        const docSnap = await rolesRef.get();
        const roles = docSnap.data();
        const usuario = roles[pin];

        if (usuario) {
            // Registramos el acceso en la auditoría
            await db.collection("artifacts/conecta-t-ecosistema/public/data/AuditoriaAccesos").add({
                usuario: usuario.nombre,
                rol: usuario.rol,
                fecha: new Date().toLocaleString(),
                ip: req.ip,
                dispositivo: req.headers['user-agent']
            });

            res.json({ 
                estatus: 'exito', 
                perfil: { 
                    nombre: usuario.nombre, 
                    rol: usuario.rol, 
                    sector: usuario.sector || 'Todos' 
                } 
            });
        } else {
            res.status(401).json({ estatus: 'error', mensaje: 'PIN Incorrecto' });
        }
    } catch (error) {
        console.error("Error en Matriz:", error);
        res.status(500).json({ estatus: 'error', mensaje: 'Error de conexión con La Matriz' });
    }
});

// --- INICIO DEL SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 BACKEND CONECTA T V2.2 LISTO EN PUERTO ${PORT}`);
});