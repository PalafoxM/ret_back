const pool = require("./db");
const { sendExpirationReminder } = require("./mailer");

const NOTICE_TYPE = "CEDULA_PROXIMA_VENCER";

const boundedInteger = (value, fallback, minimum, maximum) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) ? Math.min(maximum, Math.max(minimum, parsed)) : fallback;
};

const ensureNotificationTable = () => pool.query(`
  CREATE TABLE IF NOT EXISTS ret_notificaciones_correo (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    clave VARCHAR(100) NOT NULL,
    tipo VARCHAR(50) NOT NULL,
    fecha_referencia DATE NOT NULL,
    destinatario VARCHAR(255) NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
    intentos INT UNSIGNED NOT NULL DEFAULT 0,
    ultimo_error VARCHAR(500) NULL,
    creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enviado_en DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_notificacion_periodo (clave, tipo, fecha_referencia),
    KEY idx_notificacion_estado (tipo, estado, creado_en)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`);

async function processExpirationNotifications() {
  const noticeDays = boundedInteger(process.env.RENEWAL_NOTICE_DAYS, 30, 1, 180);
  await ensureNotificationTable();
  const [records] = await pool.execute(`
    SELECT d.clave, d.nombre_comercial,
      COALESCE(NULLIF(TRIM(account.email), ''), NULLIF(TRIM(d.correo), '')) AS destinatario,
      DATE_ADD(COALESCE(account.fecha_renovacion, d.fecha_registro), INTERVAL 3 YEAR) AS fecha_vencimiento,
      DATE_FORMAT(DATE_ADD(COALESCE(account.fecha_renovacion, d.fecha_registro), INTERVAL 3 YEAR), '%Y-%m-%d') AS fecha_vencimiento_iso,
      DATE_FORMAT(DATE_ADD(COALESCE(account.fecha_renovacion, d.fecha_registro), INTERVAL 3 YEAR), '%d/%m/%Y') AS fecha_vencimiento_texto,
      DATEDIFF(DATE_ADD(COALESCE(account.fecha_renovacion, d.fecha_registro), INTERVAL 3 YEAR), CURRENT_DATE()) AS dias_restantes
    FROM ret_datos_generales d
    LEFT JOIN (
      SELECT u.id, SUBSTRING_INDEX(GROUP_CONCAT(u.email ORDER BY u.id_usr DESC), ',', 1) AS email,
        MAX(u.fecha_renovacion) AS fecha_renovacion
      FROM ret_usr u WHERE u.activo = 1 GROUP BY u.id
    ) account ON account.id = d.clave
    WHERE d.visible = 1 AND d.aprobado = 1 AND COALESCE(d.renovar, 0) = 0
      AND COALESCE(account.fecha_renovacion, d.fecha_registro) IS NOT NULL
      AND DATEDIFF(DATE_ADD(COALESCE(account.fecha_renovacion, d.fecha_registro), INTERVAL 3 YEAR), CURRENT_DATE()) BETWEEN 0 AND ?
      AND COALESCE(NULLIF(TRIM(account.email), ''), NULLIF(TRIM(d.correo), '')) IS NOT NULL
    ORDER BY fecha_vencimiento ASC
    LIMIT 250
  `, [noticeDays]);

  let sent = 0;
  let failed = 0;
  for (const record of records) {
    const expirationKey = record.fecha_vencimiento_iso;
    const [reservation] = await pool.execute(
      `INSERT IGNORE INTO ret_notificaciones_correo
        (clave, tipo, fecha_referencia, destinatario, estado, intentos)
       VALUES (?, ?, ?, ?, 'pendiente', 1)`,
      [record.clave, NOTICE_TYPE, expirationKey, record.destinatario],
    );
    if (!reservation.affectedRows) continue;
    try {
      await sendExpirationReminder({
        to: record.destinatario,
        clave: record.clave,
        nombreComercial: record.nombre_comercial,
        expirationDate: record.fecha_vencimiento_texto,
        daysRemaining: Number(record.dias_restantes),
      });
      await pool.execute(
        "UPDATE ret_notificaciones_correo SET estado = 'enviado', enviado_en = CURRENT_TIMESTAMP WHERE id = ?",
        [reservation.insertId],
      );
      sent += 1;
    } catch (error) {
      failed += 1;
      await pool.execute("DELETE FROM ret_notificaciones_correo WHERE id = ?", [reservation.insertId]);
      console.error(`No fue posible enviar aviso de vencimiento ${record.clave}:`, error.code || error.message);
    }
  }
  console.log(`Avisos RET próximos a vencer: ${sent} enviados, ${failed} fallidos, ${records.length} candidatos.`);
  return { candidates: records.length, sent, failed };
}

function startExpirationNotificationScheduler() {
  const defaultEnabled = process.env.NODE_ENV === "production";
  const enabled = String(process.env.RENEWAL_NOTICE_ENABLED ?? defaultEnabled).toLowerCase() === "true";
  if (!enabled) {
    console.log("Avisos de vencimiento RET desactivados.");
    return () => {};
  }
  const intervalHours = boundedInteger(process.env.RENEWAL_NOTICE_INTERVAL_HOURS, 24, 1, 168);
  let running = false;
  const execute = async () => {
    if (running) return;
    running = true;
    try { await processExpirationNotifications(); }
    catch (error) { console.error("No fue posible procesar avisos de vencimiento RET:", error.code || error.message); }
    finally { running = false; }
  };
  const initialTimer = setTimeout(execute, 15_000);
  const interval = setInterval(execute, intervalHours * 60 * 60 * 1000);
  initialTimer.unref?.();
  interval.unref?.();
  return () => { clearTimeout(initialTimer); clearInterval(interval); };
}

module.exports = { processExpirationNotifications, startExpirationNotificationScheduler };
