/**
 * ============================================================================
 * SOLUCIONES PTR - MIDDLEWARE DE GOBERNANZA DE RED (MULTI-NODO)
 * ============================================================================
 * Servidor Intermedio para comunicación segura con múltiples Routers MikroTik.
 * CERO credenciales expuestas en el código fuente.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { RouterOSAPI } = require('node-routeros');

const app = express();
app.use(express.json());
app.use(cors());

// ============================================================================
// 1. EL BLINDAJE (FIREWALL DE SEGURIDAD PTR)
// ============================================================================
const verificarGafetePTR = (req, res, next) => {
    const tokenAutorizacion = req.headers['authorization'];
    
    if (tokenAutorizacion !== `Bearer ${process.env.PTR_SECRET_TOKEN}`) {
        console.log("⚠️ ALERTA DE SEGURIDAD: Intento de acceso no autorizado detectado.");
        return res.status(403).json({ estatus: 'error', mensaje: 'Gobernanza: Acceso Denegado. Credencial inválida.' });
    }
    next(); 
};

// ============================================================================
// 2. MOTOR DE CONEXIÓN DINÁMICA (MULTI-ANTENA)
// ============================================================================
// Ahora recibe la IP objetivo directamente desde La Matriz
const conectarMikroTik = (ipObjetivo) => {
    return new RouterOSAPI({
        host: ipObjetivo, // La IP de la antena que nos indique Titán
        user: process.env.MIKROTIK_USER, // Usuario estándar de la empresa
        password: process.env.MIKROTIK_PASSWORD, // Contraseña estándar maestra
        port: Number(process.env.MIKROTIK_PORT) || 8728
    });
};

// ============================================================================
// 3. RUTAS OPERATIVAS (ENDPOINTS)
// ============================================================================

app.get('/', (req, res) => {
    res.send('Servidor Multi-Nodo PTR: En línea y blindado.');
});

// B) SUSPENDER CLIENTE (Corte por Morosidad)
app.post('/api/mikrotik/suspender', verificarGafetePTR, async (req, res) => {
    const { ipCliente, ipRouter, comentario } = req.body;

    if (!ipCliente || !ipRouter) {
        return res.status(400).json({ estatus: 'error', mensaje: 'Faltan datos (IP Cliente o IP del Router).' });
    }

    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        await conn.write('/ip/firewall/address-list/add', [
            `=list=MOROSOS`,
            `=address=${ipCliente}`,
            `=comment=Suspendido por Titán: ${comentario || 'Morosidad'}`
        ]);
        conn.close();
        res.json({ estatus: 'exito', mensaje: `Cliente ${ipCliente} suspendido en el Nodo ${ipRouter}.` });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: `Falla al conectar con la antena ${ipRouter}.`, detalle: error.message });
    }
});

// C) REACTIVAR CLIENTE (Pago Recibido en Consola)
app.post('/api/mikrotik/reactivar', verificarGafetePTR, async (req, res) => {
    const { ipCliente, ipRouter } = req.body;

    if (!ipCliente || !ipRouter) {
        return res.status(400).json({ estatus: 'error', mensaje: 'Faltan datos (IP Cliente o IP del Router).' });
    }

    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        const registros = await conn.write('/ip/firewall/address-list/print', [
            `?address=${ipCliente}`,
            `?list=MOROSOS`
        ]);

        if (registros.length === 0) {
            conn.close();
            return res.json({ estatus: 'info', mensaje: 'El cliente no estaba suspendido.' });
        }

        await conn.write('/ip/firewall/address-list/remove', [
            `=.id=${registros[0]['.id']}`
        ]);
        
        conn.close();
        res.json({ estatus: 'exito', mensaje: `Internet restaurado para ${ipCliente} en el Nodo ${ipRouter}.` });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: `Falla al conectar con la antena ${ipRouter}.`, detalle: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[MATRIZ PTR] Servidor Middleware operando en el puerto ${PORT}`);
});
