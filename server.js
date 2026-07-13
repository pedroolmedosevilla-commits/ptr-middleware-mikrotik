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
const snmp = require('net-snmp');

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
// D) ENDPOINT: TELEMETRÍA DEL DASHBOARD (AHORA SOPORTA SIMPLE QUEUES)
// ============================================================================
app.post('/api/mikrotik/status', verificarGafetePTR, async (req, res) => {
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
       let totalPPPoE = 0;
       try {
           const arpTable = await conn.write('/ip/arp/print');
           const activosReales = arpTable.filter(entrada => entrada.invalid !== 'true');
           totalPPPoE = activosReales.length;
       } catch (e) { console.warn("Aviso Clientes (ARP):", e.message); }

        // --- 3. LECTURA DE TRÁFICO (INTERFAZ FÍSICA O SIMPLE QUEUE) ---
        let sumaRxBits = 0;
        const puertos = puertoWan.split(',');
        
        for (const puerto of puertos) {
            const nombrePuerto = puerto.trim();
            if(!nombrePuerto) continue;
            
            try {
                let rxBits = 0;

                // A) Si el nombre parece un puerto físico (ether, sfp, wlan, vlan)...
                if (nombrePuerto.match(/^(ether|sfp|wlan|vlan)/i)) {
                    let traffic = await conn.write('/interface/monitor-traffic', [
                        `=interface=${nombrePuerto}`, '=once='
                    ]);
                    
                    rxBits = traffic && traffic.length > 0 ? (parseFloat(traffic[0]['rx-bits-per-second']) || 0) : 0;

                    // El parche anti-micro-retraso
                    if (rxBits === 0) {
                        await new Promise(resolve => setTimeout(resolve, 200));
                        traffic = await conn.write('/interface/monitor-traffic', [
                            `=interface=${nombrePuerto}`, '=once='
                        ]);
                        rxBits = traffic && traffic.length > 0 ? (parseFloat(traffic[0]['rx-bits-per-second']) || 0) : 0;
                    }
                } 
                // B) Si no, asumimos que es un "Simple Queue" (Ej: ANCHO DE BANDA TOTAL)
                else {
                    const queue = await conn.write('/queue/simple/print', [
                        `?name=${nombrePuerto}`
                    ]);
                    
                    if (queue && queue.length > 0) {
                        const rateString = queue[0].rate || "0/0";
                        const downloadBits = rateString.split('/')[1]; // Tomamos la segunda parte
                        rxBits = parseFloat(downloadBits) || 0;
                    }
                }
                
                sumaRxBits += rxBits;
            } catch (error) {
                console.warn(`Aviso Tráfico [Puerto/Queue: ${nombrePuerto}]:`, error.message);
            }
        }
        
        const traficoRx = (sumaRxBits / 1000000).toFixed(1);

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
        
        // 🔥 EL SEGURO DE VIDA
        try { if(conn) conn.close(); } catch(e) {}
        
        res.status(200).json({ estatus: 'error', mensaje: 'Falla al conectar.' });
    }
});

// ============================================================================
// E) ENDPOINT: LECTURA HÍBRIDA DE ANTENAS (MULTI-MARCA, MULTI-VERSIÓN Y NAT)
// ============================================================================
app.post('/api/antenas/status', verificarGafetePTR, (req, res) => {
    // AHORA RECIBIMOS LA MARCA Y LA VERSIÓN DESDE EL DASHBOARD
    const { ipAntena, comunidad = 'public', marca = 'ubiquiti', version = 'v2c' } = req.body;

    if (!ipAntena) {
        return res.status(400).json({ estatus: 'error', mensaje: 'Falta la IP de la Antena.' });
    }

    // SOPORTE PARA NAT (Extraer el puerto personalizado si existe)
    const ipLimpiada = ipAntena.split(':')[0];
    const puertoSnmp = ipAntena.includes(':') ? parseInt(ipAntena.split(':')[1], 10) : 161;

    // TRADUCIR LA VERSIÓN DE REACT A FORMATO NET-SNMP
    const snmpVersion = version === 'v1' ? snmp.Version1 : snmp.Version2c;

    // CREAMOS LA SESIÓN CON LOS PARÁMETROS DINÁMICOS
    const session = snmp.createSession(ipLimpiada, comunidad, {
        port: puertoSnmp,
        version: snmpVersion,
        retries: 1, 
        timeout: 3000
    });

   // === EL DICCIONARIO DE GOBERNANZA (OIDs por fabricante) ===
   const diccionarioOIDs = {
    ubiquiti: {
        nombre: "1.3.6.1.2.1.1.5.0",             
        ccq: "1.3.6.1.4.1.41112.1.4.5.1.7.1",    
        senal: "1.3.6.1.4.1.41112.1.4.5.1.5.1",  
        ruido: "1.3.6.1.4.1.41112.1.4.5.1.8.1"   
    },
    ubiquiti_ac: {
        nombre: "1.3.6.1.2.1.1.5.0",             
        ccq: "1.3.6.1.4.1.41112.1.4.7.1.4.1",   
        senal: "1.3.6.1.4.1.41112.1.4.7.1.3.1", 
        ruido: "1.3.6.1.4.1.41112.1.4.7.1.6.1"  
    },
    mimosa: {
        nombre: "1.3.6.1.2.1.1.5.0",             
        ccq: "1.3.6.1.4.1.43356.2.1.2.9.1.2",    
        senal: "1.3.6.1.4.1.43356.2.1.2.9.1.3",  
        ruido: "1.3.6.1.4.1.43356.2.1.2.9.1.4"   
    },
    cambium: {
        nombre: "1.3.6.1.2.1.1.5.0",             
        ccq: "1.3.6.1.4.1.161.19.3.2.2.19.0",    
        senal: "1.3.6.1.4.1.161.19.3.2.2.22.0",  
        ruido: "1.3.6.1.4.1.161.19.3.2.2.21.0"   
    }
};

    // Seleccionamos los OIDs dependiendo de la marca que mandó el Dashboard
    const oidsUsar = diccionarioOIDs[marca.toLowerCase()] || diccionarioOIDs['ubiquiti'];
    const oidsArray = [oidsUsar.nombre, oidsUsar.ccq, oidsUsar.senal, oidsUsar.ruido];

    session.get(oidsArray, (error, varbinds) => {
        if (error) {
            session.close();
            return res.status(500).json({ estatus: 'error', mensaje: `Falla SNMP: ${error.toString()}` });
        }

        let datosAntena = { nombre: 'Desconocido', ccq: 0, senal: 0, ruido: 0 };
        
        for (let i = 0; i < varbinds.length; i++) {
            if (!snmp.isVarbindError(varbinds[i])) {
                let valor = varbinds[i].value;
                if (Buffer.isBuffer(valor)) valor = valor.toString();
                
                // Hacemos match con el diccionario
                if (varbinds[i].oid === oidsUsar.nombre) datosAntena.nombre = valor;
                if (varbinds[i].oid === oidsUsar.ccq) datosAntena.ccq = parseInt(valor) || 0;
                if (varbinds[i].oid === oidsUsar.senal) datosAntena.senal = parseInt(valor) || 0;
                if (varbinds[i].oid === oidsUsar.ruido) datosAntena.ruido = parseInt(valor) || 0;
            }
        }

        session.close();
        res.json({ estatus: 'exito', datos: datosAntena });
    });
});

// ============================================================================
// F) ENDPOINT: LISTAR CLIENTES PPPoE ACTIVOS (PARA MODAL EN DASHBOARD)
// ============================================================================
app.post('/api/mikrotik/clientes-activos', verificarGafetePTR, async (req, res) => {
    const { ipRouter } = req.body;

    if (!ipRouter) return res.status(400).json({ estatus: 'error', mensaje: 'Falta IP del Router' });

    const conn = conectarMikroTik(ipRouter);
    try {
        await conn.connect();
        const activos = await conn.write('/ppp/active/print');
        
        // Limpiamos los datos para mandar solo lo necesario a React
        const listaLimpia = activos.map(c => ({
            nombre: c.name || 'Desconocido',
            ip: c.address || 'Sin IP',
            uptime: c.uptime || '0s'
        }));

        conn.close();
        res.json({ estatus: 'exito', clientes: listaLimpia });
    } catch (error) {
        if(conn) conn.close();
        res.status(500).json({ estatus: 'error', mensaje: 'Falla al extraer clientes', detalle: error.message });
    }
});

// === DECLARAMOS EL PUERTO PARA QUE RENDER LO INYECTE ===
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`[MATRIZ PTR] Servidor Middleware operando en el puerto ${PORT}`);
});