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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
