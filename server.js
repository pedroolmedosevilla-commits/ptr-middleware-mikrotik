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
const conectarMikroTik = (ipObjetivo) => {
    // Dividimos el string para ver si trae puerto (ej: "201.x.x.x:8713")
    const partes = ipObjetivo.split(':');
    const host = partes[0];
    // Si trae puerto, lo usamos; si no, usamos el de las variables de entorno
    const puerto = partes[1] ? parseInt(partes[1], 10) : (parseInt(process.env.MIKROTIK_PORT, 10) || 8728);

    console.log(`[MATRIZ PTR] Intentando conectar a: ${host} | Puerto: ${puerto}`);

    return new RouterOSAPI({
        host: host,
        user: process.env.MIKROTIK_USER,
        password: process.env.MIKROTIK_PASSWORD,
        port: puerto
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

// ============================================================================
// D) ENDPOINT: TELEMETRÍA DEL DASHBOARD (MULTI-PUERTO BLINDADO)
// ============================================================================
app.post('/api/mikrotik/status', verificarGafetePTR, async (req, res) => {
    // AHORA EL SERVIDOR RECIBE EL PUERTO DINÁMICO DESDE LA APP
    const { ipRouter, puertoWan = 'ether1' } = req.body; 
    if (!ipRouter) return res.status(400).json({ estatus: 'error', mensaje: 'Faltan datos' });

    const conn = conectarMikroTik(ipRouter);

    try {
        await conn.connect();
        
        const recursos = await conn.write('/system/resource/print');
        
        // --- 1. LECTURA DE TEMPERATURA ---
        let temperaturaReal = 0;
        try {
            const salud = await conn.write('/system/health/print');
            if (salud && salud.length > 0) {
                const sensorTemp = salud.find(s => s.name && s.name.includes('temperature'));
                temperaturaReal = sensorTemp ? parseFloat(sensorTemp.value) : (salud[0].temperature ? parseFloat(salud[0].temperature) : 0);
            }
        } catch (e) { console.warn("Aviso Temperatura:", e.message); }

       // --- 2. LECTURA DE CLIENTES (IPs ESTÁTICAS ACTIVAS VÍA ARP) ---
       let totalPPPoE = 0; // Se llama PPPoE por compatibilidad con la App, pero cuenta IPs Activas
       try {
           // Le pedimos al router la tabla ARP (Equipos físicamente comunicándose)
           const arpTable = await conn.write('/ip/arp/print');
           
           // Filtramos un poco para ser precisos (opcional, pero buena práctica)
           // Filtramos las entradas "inválidas" o "completas" para contar solo los dispositivos reales
           const activosReales = arpTable.filter(entrada => entrada.invalid !== 'true');
           
           totalPPPoE = activosReales.length;
       } catch (e) { 
           console.warn("Aviso Clientes (ARP):", e.message); 
       }

        // --- 3. LECTURA DE TRÁFICO (SOPORTA MÚLTIPLES PUERTOS SEPARADOS POR COMA) ---
        let sumaRxBits = 0;
        const puertos = puertoWan.split(','); // Separa los puertos inteligentemente
        
        for (const puerto of puertos) {
            const nombrePuerto = puerto.trim(); // Quita espacios extra por si acaso
            if(!nombrePuerto) continue;
            
            try {
                const traffic = await conn.write('/interface/monitor-traffic', [
                    `=interface=${nombrePuerto}`,
                    '=once='
                ]);
                
                if (traffic && traffic.length > 0) {
                    sumaRxBits += parseFloat(traffic[0]['rx-bits-per-second']) || 0;
                }
            } catch (e) { 
                // SI ALGO FALLA, LE AVISARÁ A FER EXACTAMENTE QUÉ PUERTO ESTÁ MAL ESCRITO
                console.warn(`Aviso Tráfico [Puerto: ${nombrePuerto}]:`, e.message); 
            }
        }
        
        const traficoRx = (sumaRxBits / 1000000).toFixed(1); // Convierte a Mbps

        conn.close();

        // --- 4. CÁLCULO DE RAM ---
        const data = recursos[0];
        const totalRam = parseInt(data['total-memory']);
        const freeRam = parseInt(data['free-memory']);
        const porcentajeRam = ((totalRam - freeRam) / totalRam * 100).toFixed(1);

        res.json({
            estatus: 'exito',
            data: {
                cpu: data['cpu-load'],
                ram: porcentajeRam,
                temp: temperaturaReal, 
                rx: traficoRx,
                activos: totalPPPoE
            }
        });

    } catch (error) {
        console.error("Error Crítico de Conexión:", error.message);
        res.status(500).json({ estatus: 'error', mensaje: `Falla al conectar.` });
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[MATRIZ PTR] Servidor Middleware operando en el puerto ${PORT}`);
});
