/**
 * ============================================================================
 * SOLUCIONES PTR - MIDDLEWARE DE GOBERNANZA DE RED
 * ============================================================================
 * Servidor Intermedio para comunicación segura con Routers MikroTik.
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
    
    // Si la orden no trae el Gafete Oficial de la Matriz, la rechazamos al instante.
    if (tokenAutorizacion !== `Bearer ${process.env.PTR_SECRET_TOKEN}`) {
        console.log("⚠️ ALERTA DE SEGURIDAD: Intento de acceso no autorizado detectado.");
        return res.status(403).json({ estatus: 'error', mensaje: 'Gobernanza: Acceso Denegado. Credencial inválida.' });
    }
    next(); // Pasa el filtro, procede a ejecutar la orden.
};

// ============================================================================
// 2. MOTOR DE CONEXIÓN A LA ANTENA MIKROTIK
// ============================================================================
const conectarMikroTik = () => {
    return new RouterOSAPI({
        host: process.env.MIKROTIK_IP,
        user: process.env.MIKROTIK_USER,
        password: process.env.MIKROTIK_PASSWORD,
        port: Number(process.env.MIKROTIK_PORT) || 8728
    });
};

// ============================================================================
// 3. RUTAS OPERATIVAS (ENDPOINTS)
// ============================================================================

// A) RUTA DE PRUEBA (Para saber si el servidor está vivo)
app.get('/', (req, res) => {
    res.send('Servidor de Ingeniería PTR: En línea y blindado.');
});

// B) SUSPENDER CLIENTE (Corte por Morosidad)
app.post('/api/mikrotik/suspender', verificarGafetePTR, async (req, res) => {
    const { ipCliente, comentario } = req.body;

    if (!ipCliente) {
        return res.status(400).json({ estatus: 'error', mensaje: 'Falta la IP o PPPoE del cliente.' });
    }

    const conn = conectarMikroTik();
    try {
        await conn.connect();
        // Agrega la IP a la lista de "MOROSOS" en el Firewall del MikroTik
        await conn.write('/ip/firewall/address-list/add', [
            `=list=MOROSOS`,
            `=address=${ipCliente}`,
            `=comment=Suspendido por Titán: ${comentario || 'Morosidad'}`
        ]);
        conn.close();
        res.json({ estatus: 'exito', mensaje: `Cliente ${ipCliente} suspendido correctamente.` });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: 'Falla al conectar con la antena.', detalle: error.message });
    }
});

// C) REACTIVAR CLIENTE (Pago Recibido en Consola)
app.post('/api/mikrotik/reactivar', verificarGafetePTR, async (req, res) => {
    const { ipCliente } = req.body;

    if (!ipCliente) {
        return res.status(400).json({ estatus: 'error', mensaje: 'Falta la IP o PPPoE del cliente.' });
    }

    const conn = conectarMikroTik();
    try {
        await conn.connect();
        // 1. Buscamos el ID interno de esa IP en la lista de MOROSOS
        const registros = await conn.write('/ip/firewall/address-list/print', [
            `?address=${ipCliente}`,
            `?list=MOROSOS`
        ]);

        if (registros.length === 0) {
            conn.close();
            return res.json({ estatus: 'info', mensaje: 'El cliente no estaba suspendido.' });
        }

        // 2. Borramos el registro (Le regresa el internet)
        await conn.write('/ip/firewall/address-list/remove', [
            `=.id=${registros[0]['.id']}`
        ]);
        
        conn.close();
        res.json({ estatus: 'exito', mensaje: `Internet restaurado para ${ipCliente}.` });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: 'Falla al conectar con la antena.', detalle: error.message });
    }
});

// ============================================================================
// 4. ENCENDIDO DEL SERVIDOR
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[MATRIZ PTR] Servidor Middleware operando en el puerto ${PORT}`);
});
