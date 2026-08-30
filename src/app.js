const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { rateLimit } = require("express-rate-limit");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const pool = require("./db");
const { sendRegistrationCredentials, sendPasswordRecovery } = require("./mailer");

const app = express();
const uploadsRoot = path.resolve(__dirname, "../uploads");
const temporaryUploads = path.join(uploadsRoot, "tmp");
fs.mkdirSync(temporaryUploads, { recursive: true });
const legalUpload = multer({
  dest: temporaryUploads,
  limits: { fileSize: 10 * 1024 * 1024, files: 9 },
  fileFilter: (req, file, callback) => callback(null, ["application/pdf", "image/png", "image/jpeg"].includes(file.mimetype)),
});
const LEGAL_FIELDS = Object.freeze({
  rfc: "rfc", curp: "curp", ife: "ife", licencia_suelo: "licencia_suelo",
  escritura_publica: "escritura_publica", acta_constitutiva: "acta_constitutiva",
  rfc_legal: "rfc_legal", domicilio: "domicilio", protocolo_higiene: "protocolo_higiene",
});
const GRAPHIC_FIELDS = Object.freeze({
  imagen_promocional: "imagen_promocional", logo: "logo", imagen1: "imagen1",
  imagen2: "imagen2", imagen3: "imagen3",
});
const graphicUpload = multer({
  dest: temporaryUploads,
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, callback) => callback(null, ["image/png", "image/jpeg"].includes(file.mimetype)),
});
const getImageDimensions = (buffer, mimeType) => {
  if (mimeType === "image/png" && buffer.length >= 24 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
  }
  if (mimeType === "image/jpeg" && buffer.length > 4 && buffer[0] === 0xff && buffer[1] === 0xd8) {
    const startOfFrame = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
    let offset = 2;
    while (offset + 8 < buffer.length) {
      if (buffer[offset] !== 0xff) { offset += 1; continue; }
      const marker = buffer[offset + 1];
      if (startOfFrame.has(marker)) return { height: buffer.readUInt16BE(offset + 5), width: buffer.readUInt16BE(offset + 7) };
      if (marker === 0xd8 || marker === 0xd9) { offset += 2; continue; }
      const segmentLength = buffer.readUInt16BE(offset + 2);
      if (segmentLength < 2) break;
      offset += 2 + segmentLength;
    }
  }
  return null;
};

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("dev"));

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "API del RET funcionando correctamente",
  });
});

const SESSION_COOKIE = "ret_session";
const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  return typeof secret === "string" && secret.length >= 32 ? secret : null;
};

const requireAuth = (req, res, next) => {
  const secret = getJwtSecret();
  if (!secret) {
    return res.status(503).json({ success: false, message: "La autenticación no está configurada" });
  }
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return res.status(401).json({ success: false, message: "Sesión requerida" });
  try {
    req.auth = jwt.verify(token, secret, { algorithms: ["HS256"], issuer: "ret-api", audience: "ret-web" });
    next();
  } catch {
    res.clearCookie(SESSION_COOKIE, { path: "/" });
    return res.status(401).json({ success: false, message: "La sesión expiró o no es válida" });
  }
};

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { success: false, message: "Demasiados intentos. Intenta nuevamente en 15 minutos" },
});

const recoveryLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { success: false, message: "Demasiadas solicitudes de recuperación. Intenta nuevamente más tarde" },
});

app.post("/api/auth/login", loginLimiter, async (req, res, next) => {
  const secret = getJwtSecret();
  if (!secret) {
    return res.status(503).json({ success: false, message: "La autenticación no está configurada" });
  }
  const clave = String(req.body.clave || "").trim().toUpperCase();
  const password = String(req.body.password || "");
  if (!/^RET\d{6,14}$/.test(clave) || !password || password.length > 128) {
    return res.status(401).json({ success: false, message: "Clave RET o contraseña incorrecta" });
  }

  try {
    const [[user]] = await pool.execute(
      `SELECT u.id_usr, u.id, u.pass, u.email, u.id_perfil, u.activo,
              d.nombre_comercial, d.giro, d.porcentaje_registro
       FROM ret_usr u
       LEFT JOIN ret_datos_generales d ON d.clave = u.id
       WHERE u.id = ? LIMIT 1`,
      [clave],
    );
    if (!user || Number(user.activo) !== 1) {
      return res.status(401).json({ success: false, message: "Clave RET o contraseña incorrecta" });
    }

    let passwordMatches = false;
    const usesBcrypt = /^\$2[aby]\$/.test(user.pass || "");
    if (usesBcrypt) passwordMatches = await bcrypt.compare(password, user.pass);
    else if (/^[a-f0-9]{32}$/i.test(user.pass || "")) {
      const legacyHash = crypto.createHash("md5").update(password).digest("hex");
      passwordMatches = crypto.timingSafeEqual(Buffer.from(legacyHash), Buffer.from(user.pass.toLowerCase()));
    }
    if (!passwordMatches) {
      return res.status(401).json({ success: false, message: "Clave RET o contraseña incorrecta" });
    }

    if (!usesBcrypt) {
      const upgradedHash = await bcrypt.hash(password, 12);
      await pool.execute("UPDATE ret_usr SET pass = ? WHERE id_usr = ?", [upgradedHash, user.id_usr]);
    }

    const maxAge = 8 * 60 * 60 * 1000;
    const token = jwt.sign(
      { sub: String(user.id_usr), clave: user.id, perfil: user.id_perfil },
      secret,
      { algorithm: "HS256", expiresIn: Math.floor(maxAge / 1000), issuer: "ret-api", audience: "ret-web", jwtid: crypto.randomUUID() },
    );
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge,
    });
    res.status(200).json({ success: true, data: {
      clave: user.id, email: user.email, nombre_comercial: user.nombre_comercial,
      giro: user.giro, porcentaje_registro: user.porcentaje_registro,
      session_expires_at: Date.now() + maxAge,
    } });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/recuperar-password", recoveryLimiter, async (req, res) => {
  const correo = String(req.body.email || req.body.correo || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo) || correo.length > 254) {
    return res.status(400).json({ success: false, message: "Ingresa un correo electrónico válido" });
  }

  const genericResponse = {
    success: true,
    message: "Si el correo está registrado y activo, recibirás nuevas credenciales de acceso",
  };
  const temporaryPassword = generatePassword();
  const passwordHash = await bcrypt.hash(temporaryPassword, 12);
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[user]] = await connection.execute(
      `SELECT u.id_usr, u.id AS clave, u.email, u.activo, d.nombre_comercial
       FROM ret_usr u LEFT JOIN ret_datos_generales d ON d.clave = u.id
       WHERE LOWER(u.email) = ? LIMIT 1 FOR UPDATE`,
      [correo],
    );
    if (!user || Number(user.activo) !== 1) {
      await connection.rollback();
      return res.status(200).json(genericResponse);
    }

    await sendPasswordRecovery({
      to: user.email,
      clave: user.clave,
      temporaryPassword,
      nombreComercial: user.nombre_comercial,
    });
    await connection.execute("UPDATE ret_usr SET pass = ? WHERE id_usr = ?", [passwordHash, user.id_usr]);
    await connection.commit();
    return res.status(200).json(genericResponse);
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("No fue posible procesar la recuperación de acceso:", error.code || error.message);
    return res.status(200).json(genericResponse);
  } finally {
    if (connection) connection.release();
  }
});

app.get("/api/auth/me", requireAuth, async (req, res, next) => {
  try {
    const [[user]] = await pool.execute(
      `SELECT u.id AS clave, u.email, u.id_perfil, u.activo,
              d.nombre_comercial, d.giro, d.municipio, d.porcentaje_registro
       FROM ret_usr u LEFT JOIN ret_datos_generales d ON d.clave = u.id
       WHERE u.id_usr = ? AND u.id = ? LIMIT 1`,
      [req.auth.sub, req.auth.clave],
    );
    if (!user || Number(user.activo) !== 1) return res.status(401).json({ success: false, message: "Sesión no válida" });
    res.status(200).json({ success: true, data: { ...user, session_expires_at: Number(req.auth.exp) * 1000 } });
  } catch (error) {
    next(error);
  }
});

app.get("/api/mis-registros", requireAuth, async (req, res, next) => {
  try {
    const [[owner]] = await pool.execute(
      "SELECT email FROM ret_usr WHERE id_usr = ? AND id = ? AND activo = 1 LIMIT 1",
      [req.auth.sub, req.auth.clave],
    );
    if (!owner) return res.status(401).json({ success: false, message: "La sesión ya no es válida" });
    const [rows] = await pool.execute(
      `SELECT u.id AS clave, d.nombre_comercial, d.info_rfc AS rfc, d.porcentaje_registro, d.giro AS id_giro,
              g.resumen AS giro, m.municipio
       FROM ret_usr u
       JOIN ret_datos_generales d ON d.clave = u.id
       LEFT JOIN ret_giro g ON g.id_giro = d.giro
       LEFT JOIN ret_municipio m ON m.id_municipio = d.municipio
       WHERE LOWER(u.email) = LOWER(?) AND u.activo = 1
       ORDER BY d.fecha_registro DESC, d.id_pts DESC`,
      [owner.email],
    );
    res.status(200).json({ success: true, data: rows.map((row) => ({ ...row, actual: row.clave === req.auth.clave })) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/mis-registros/:clave/seleccionar", requireAuth, async (req, res, next) => {
  const clave = String(req.params.clave || "").trim().toUpperCase();
  if (!/^RET\d{6,14}$/.test(clave)) return res.status(400).json({ success: false, message: "La clave RET no es válida" });
  try {
    const [[target]] = await pool.execute(
      `SELECT target.id_usr, target.id AS clave, target.id_perfil, target.email,
              d.nombre_comercial, d.giro, d.municipio, d.porcentaje_registro
       FROM ret_usr current_account
       JOIN ret_usr target ON LOWER(target.email) = LOWER(current_account.email) AND target.id = ? AND target.activo = 1
       JOIN ret_datos_generales d ON d.clave = target.id
       WHERE current_account.id_usr = ? AND current_account.id = ? AND current_account.activo = 1
       LIMIT 1`,
      [clave, req.auth.sub, req.auth.clave],
    );
    if (!target) return res.status(404).json({ success: false, message: "El establecimiento no pertenece a tu cuenta" });
    const secret = getJwtSecret();
    const maxAge = 8 * 60 * 60 * 1000;
    const token = jwt.sign(
      { sub: String(target.id_usr), clave: target.clave, perfil: target.id_perfil },
      secret,
      { algorithm: "HS256", expiresIn: Math.floor(maxAge / 1000), issuer: "ret-api", audience: "ret-web", jwtid: crypto.randomUUID() },
    );
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge,
    });
    res.status(200).json({ success: true, message: "Establecimiento seleccionado", data: {
      clave: target.clave,
      email: target.email,
      nombre_comercial: target.nombre_comercial,
      giro: target.giro,
      municipio: target.municipio,
      porcentaje_registro: target.porcentaje_registro,
      session_expires_at: Date.now() + maxAge,
    } });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/mis-registros/:clave", requireAuth, async (req, res, next) => {
  const clave = String(req.params.clave || "").trim().toUpperCase();
  if (!/^RET\d{6,14}$/.test(clave)) return res.status(400).json({ success: false, message: "La clave RET no es válida" });
  if (clave === req.auth.clave) return res.status(409).json({ success: false, message: "Selecciona otro establecimiento antes de eliminar el registro actual" });
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[target]] = await connection.execute(
      `SELECT target.id_usr
       FROM ret_usr current_account
       JOIN ret_usr target ON LOWER(target.email) = LOWER(current_account.email) AND target.id = ? AND target.activo = 1
       WHERE current_account.id_usr = ? AND current_account.id = ? AND current_account.activo = 1
       LIMIT 1 FOR UPDATE`,
      [clave, req.auth.sub, req.auth.clave],
    );
    if (!target) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "El establecimiento no pertenece a tu cuenta" });
    }
    await connection.execute("UPDATE ret_usr SET activo = 0 WHERE id_usr = ?", [target.id_usr]);
    await connection.execute("UPDATE ret_datos_generales SET visible = 0 WHERE clave = ?", [clave]);
    await connection.commit();
    res.status(200).json({ success: true, message: "El registro fue desactivado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/" });
  res.status(200).json({ success: true });
});

app.get("/api/form/datos-generales", requireAuth, async (req, res, next) => {
  try {
    const [[data]] = await pool.execute(
      `SELECT d.nombre_comercial, d.contacto, d.tipo_persona, d.info_rfc, d.razon_social,
              d.representante_moral, d.idgiro_subrubro, d.calle, d.numero, d.interior, d.colonia,
              d.municipio, m.municipio AS municipio_nombre, d.cp, d.telefono,
              d.telefono_comercial, d.telefono2, d.web, d.correo, d.correo_atncli,
              d.facebook, d.twitter, d.h, d.m, d.tesoros, d.iso, d.punto_limpio,
              d.anfitrion, d.estandares, d.otro, d.otrocertificacion, d.descripcion,
              d.protesto_juridico, d.aviso_descripcion,
              d.latitud, d.longitud, d.giro
       FROM ret_datos_generales d
       LEFT JOIN ret_municipio m ON m.id_municipio = d.municipio
       WHERE d.clave = ? LIMIT 1`,
      [req.auth.clave],
    );
    if (!data) return res.status(404).json({ success: false, message: "No se encontró el establecimiento" });
    const [subrubros] = await pool.execute(
      "SELECT idgiro_subrubro, descripcion FROM ret_giro_subrubro WHERE id_giro = ? ORDER BY descripcion",
      [data.giro],
    );
    res.status(200).json({ success: true, data, subrubros });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/datos-generales", requireAuth, async (req, res, next) => {
  const text = (name, max) => String(req.body[name] ?? "").trim().slice(0, max);
  const required = ["contacto", "razon_social", "calle", "numero", "colonia", "cp", "telefono", "telefono_comercial", "correo_atncli", "descripcion"];
  if (required.some((field) => !text(field, 300))) {
    return res.status(400).json({ success: false, message: "Completa todos los campos obligatorios" });
  }
  const tipoPersona = Number.parseInt(req.body.tipo_persona, 10);
  const subrubro = Number.parseInt(req.body.idgiro_subrubro, 10);
  const latitud = Number(req.body.latitud);
  const rawLongitud = Number(req.body.longitud);
  const longitud = rawLongitud > 0 ? -rawLongitud : rawLongitud;
  if (![1, 2].includes(tipoPersona) || !Number.isInteger(subrubro)) {
    return res.status(400).json({ success: false, message: "Selecciona el tipo de persona y subrubro" });
  }
  const accepted = (name) => req.body[name] === true || req.body[name] === 1 || req.body[name] === "1";
  if (!accepted("protesto_juridico") || !accepted("aviso_descripcion")) {
    return res.status(400).json({ success: false, message: "Debes aceptar ambas declaraciones obligatorias" });
  }
  if (!Number.isFinite(latitud) || !Number.isFinite(longitud) || latitud < 14 || latitud > 33 || longitud < -119 || longitud > -86) {
    return res.status(400).json({ success: false, message: "Selecciona una ubicación válida en el mapa" });
  }
  try {
    const [[validSubrubro]] = await pool.execute(
      `SELECT s.idgiro_subrubro FROM ret_giro_subrubro s
       JOIN ret_datos_generales d ON d.giro = s.id_giro
       WHERE d.clave = ? AND s.idgiro_subrubro = ? LIMIT 1`,
      [req.auth.clave, subrubro],
    );
    if (!validSubrubro) return res.status(400).json({ success: false, message: "El subrubro no corresponde al giro" });
    const bool = (name) => req.body[name] === true || req.body[name] === 1 || req.body[name] === "1" ? 1 : 0;
    await pool.execute(
      `UPDATE ret_datos_generales SET
        porcentaje_registro=10, contacto=?, tipo_persona=?, razon_social=?, representante_moral=?, idgiro_subrubro=?,
        calle=?, numero=?, interior=?, colonia=?, cp=?, telefono=?, telefono_comercial=?,
        telefono2=?, web=?, correo_atncli=?, facebook=?, twitter=?, h=?, m=?, tesoros=?,
        iso=?, punto_limpio=?, anfitrion=?, estandares=?, otro=?, otrocertificacion=?,
        descripcion=?, latitud=?, longitud=?, protesto_juridico=?, aviso_descripcion=? WHERE clave=?`,
      [text("contacto", 100), tipoPersona, text("razon_social", 255), text("representante_moral", 60), subrubro,
       text("calle", 120), text("numero", 10), text("interior", 5), text("colonia", 50), text("cp", 10),
       text("telefono", 10), text("telefono_comercial", 10), text("telefono2", 10), text("web", 50),
       text("correo_atncli", 120), text("facebook", 250), text("twitter", 250), bool("h"), bool("m"),
       bool("tesoros"), bool("iso"), bool("punto_limpio"), bool("anfitrion"), bool("estandares"), bool("otro"),
       text("otrocertificacion", 50), text("descripcion", 10000), String(latitud), String(longitud),
       bool("protesto_juridico"), bool("aviso_descripcion"), req.auth.clave],
    );
    res.status(200).json({ success: true, message: "Datos generales guardados correctamente" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/form/datos-tecnicos", requireAuth, async (req, res, next) => {
  try {
    const [[data]] = await pool.execute(
      `SELECT t.fijos_h, t.fijos_m, t.tempo_h, t.tempo_m, t.disca_h, t.disca_m,
              t.capacita, t.cert_med, t.inst_disca, t.lgbttit, t.pet_friendly,
              t.inversion, COALESCE(NULLIF(t.inicio_opera, ''), DATE_FORMAT(d.fecha_inicio_operacion, '%Y-%m-%d')) AS inicio_opera,
              t.organizacion, t.local, t.regional, t.nacional, t.internacional, t.cadenaper
       FROM ret_frm_tecnicos t
       LEFT JOIN ret_datos_generales d ON d.clave = t.clave
       WHERE t.clave = ? LIMIT 1`,
      [req.auth.clave],
    );
    if (!data) return res.status(404).json({ success: false, message: "No se encontró el formulario técnico" });
    res.status(200).json({ success: true, data });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/datos-tecnicos", requireAuth, async (req, res, next) => {
  const count = (name) => Number.parseInt(req.body[name], 10);
  const counts = ["fijos_h", "fijos_m", "tempo_h", "tempo_m", "disca_h", "disca_m"];
  if (counts.some((name) => !Number.isInteger(count(name)) || count(name) < 0 || count(name) > 9999)) {
    return res.status(400).json({ success: false, message: "Las cantidades de personal deben ser números entre 0 y 9999" });
  }
  const binary = (name) => {
    const value = String(req.body[name] ?? "").toUpperCase();
    return value === "1" || value === "SI" ? 1 : value === "0" || value === "NO" ? 0 : null;
  };
  const yesNoFields = ["capacita", "cert_med", "inst_disca", "lgbttit", "pet_friendly"];
  if (yesNoFields.some((name) => binary(name) === null)) {
    return res.status(400).json({ success: false, message: "Selecciona una opción en todos los campos obligatorios" });
  }
  const inversion = String(req.body.inversion || "").trim().slice(0, 30);
  const inicioOpera = String(req.body.inicio_opera || "").trim();
  const organizacion = String(req.body.organizacion || "").trim().slice(0, 22);
  if (!inversion || !organizacion || !/^\d{4}-\d{2}-\d{2}$/.test(inicioOpera)) {
    return res.status(400).json({ success: false, message: "Completa inversión, organización y fecha de inicio" });
  }
  const market = (name) => req.body[name] === true || req.body[name] === 1 || req.body[name] === "1" ? 1 : 0;
  const markets = [market("local"), market("regional"), market("nacional"), market("internacional")];
  if (!markets.some(Boolean)) {
    return res.status(400).json({ success: false, message: "Selecciona al menos un tipo de mercado" });
  }
  try {
    const [result] = await pool.execute(
      `UPDATE ret_frm_tecnicos SET porcentaje_registro=10,
        fijos_h=?, fijos_m=?, tempo_h=?, tempo_m=?, disca_h=?, disca_m=?, capacita=?,
        cert_med=?, inst_disca=?, lgbttit=?, pet_friendly=?, inversion=?, inicio_opera=?,
        organizacion=?, local=?, regional=?, nacional=?, internacional=?, cadenaper=?
       WHERE clave=?`,
      [count("fijos_h"), count("fijos_m"), count("tempo_h"), count("tempo_m"), count("disca_h"), count("disca_m"),
       binary("capacita"), binary("cert_med"), binary("inst_disca") ? "SI" : "NO", binary("lgbttit") ? "SI" : "NO",
       binary("pet_friendly") ? "SI" : "NO", inversion, inicioOpera, organizacion,
       markets[0], markets[1], markets[2], markets[3], String(req.body.cadenaper || "").trim().slice(0, 150), req.auth.clave],
    );
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "No se encontró el formulario técnico" });
    res.status(200).json({ success: true, message: "Datos técnicos guardados correctamente" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/form/datos-legales", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT a.rfc, a.curp, a.ife, a.licencia_suelo, a.escritura_publica,
              a.acta_constitutiva, a.rfc_legal, a.domicilio, a.protocolo_higiene,
              d.tipo_persona, d.giro
       FROM ret_archivo_legal a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el expediente legal" });
    const files = Object.fromEntries(Object.keys(LEGAL_FIELDS).map((field) => [field, Boolean(row[field])]));
    res.status(200).json({ success: true, data: { files, tipo_persona: row.tipo_persona, giro: row.giro } });
  } catch (error) {
    next(error);
  }
});

app.get("/api/form/datos-legales/archivo/:field", requireAuth, async (req, res, next) => {
  const column = LEGAL_FIELDS[req.params.field];
  if (!column) return res.status(404).json({ success: false, message: "Archivo no válido" });
  try {
    const [[row]] = await pool.query("SELECT ?? AS file_path FROM ret_archivo_legal WHERE clave = ? LIMIT 1", [column, req.auth.clave]);
    if (!row?.file_path) return res.status(404).json({ success: false, message: "Archivo no encontrado" });
    const absolutePath = path.resolve(uploadsRoot, row.file_path);
    if (!absolutePath.startsWith(`${uploadsRoot}${path.sep}`)) return res.status(400).json({ success: false, message: "Ruta de archivo no válida" });
    res.sendFile(absolutePath);
  } catch (error) {
    next(error);
  }
});

app.post("/api/form/datos-legales", requireAuth, legalUpload.fields(Object.keys(LEGAL_FIELDS).map((name) => ({ name, maxCount: 1 }))), async (req, res, next) => {
  const uploadedFiles = Object.values(req.files || {}).flat();
  const cleanTemporaryFiles = async () => Promise.all(uploadedFiles.map((file) => fsp.unlink(file.path).catch(() => {})));
  try {
    const signatures = { "application/pdf": Buffer.from("%PDF"), "image/png": Buffer.from([0x89, 0x50, 0x4e, 0x47]), "image/jpeg": Buffer.from([0xff, 0xd8, 0xff]) };
    for (const file of uploadedFiles) {
      const handle = await fsp.open(file.path, "r");
      const header = Buffer.alloc(4);
      await handle.read(header, 0, 4, 0);
      await handle.close();
      const expected = signatures[file.mimetype];
      if (!expected || !header.subarray(0, expected.length).equals(expected)) {
        await cleanTemporaryFiles();
        return res.status(400).json({ success: false, message: "Uno de los archivos no coincide con su formato declarado" });
      }
    }

    const [[current]] = await pool.execute(
      `SELECT a.rfc, a.curp, a.ife, a.licencia_suelo, a.escritura_publica,
              a.acta_constitutiva, a.rfc_legal, a.domicilio, a.protocolo_higiene,
              d.tipo_persona, d.giro
       FROM ret_archivo_legal a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? LIMIT 1`,
      [req.auth.clave],
    );
    if (!current) {
      await cleanTemporaryFiles();
      return res.status(404).json({ success: false, message: "No se encontró el expediente legal" });
    }
    const incoming = (field) => Boolean(req.files?.[field]?.[0]);
    const required = ["rfc", "ife", "licencia_suelo", "escritura_publica", "domicilio"];
    if (Number(current.tipo_persona) === 2) required.push("acta_constitutiva", "rfc_legal");
    if (Number(current.giro) === 17) required.push("protocolo_higiene");
    const missing = required.filter((field) => !current[field] && !incoming(field));
    if (missing.length) {
      await cleanTemporaryFiles();
      return res.status(400).json({ success: false, message: "Adjunta todos los documentos obligatorios" });
    }

    const legalDirectory = path.join(uploadsRoot, "legal", req.auth.clave);
    await fsp.mkdir(legalDirectory, { recursive: true });
    const extensions = { "application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg" };
    const updates = [];
    const values = [];
    for (const [field, files] of Object.entries(req.files || {})) {
      const file = files[0];
      const filename = `${field}-${crypto.randomUUID()}${extensions[file.mimetype]}`;
      const destination = path.join(legalDirectory, filename);
      await fsp.rename(file.path, destination);
      updates.push("?? = ?");
      values.push(LEGAL_FIELDS[field], path.relative(uploadsRoot, destination).replaceAll(path.sep, "/"));
    }
    if (updates.length) {
      await pool.query(`UPDATE ret_archivo_legal SET porcentaje_registro = 40, ${updates.join(", ")} WHERE clave = ?`, [...values, req.auth.clave]);
    } else {
      await pool.execute("UPDATE ret_archivo_legal SET porcentaje_registro = 40 WHERE clave = ?", [req.auth.clave]);
    }
    res.status(200).json({ success: true, message: "Documentos legales guardados correctamente" });
  } catch (error) {
    await cleanTemporaryFiles();
    next(error);
  }
});

app.get("/api/form/datos-graficos", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      "SELECT imagen_promocional, logo, imagen1, imagen2, imagen3, promocion_gtomx FROM ret_archivo_legal WHERE clave = ? LIMIT 1",
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el expediente gráfico" });
    const files = Object.fromEntries(Object.keys(GRAPHIC_FIELDS).map((field) => [field, Boolean(row[field])]));
    res.status(200).json({ success: true, data: { files, promocion_gtomx: row.promocion_gtomx } });
  } catch (error) {
    next(error);
  }
});

app.get("/api/form/datos-graficos/archivo/:field", requireAuth, async (req, res, next) => {
  const column = GRAPHIC_FIELDS[req.params.field];
  if (!column) return res.status(404).json({ success: false, message: "Imagen no válida" });
  try {
    const [[row]] = await pool.query("SELECT ?? AS file_path FROM ret_archivo_legal WHERE clave = ? LIMIT 1", [column, req.auth.clave]);
    if (!row?.file_path) return res.status(404).json({ success: false, message: "Imagen no encontrada" });
    const absolutePath = path.resolve(uploadsRoot, row.file_path);
    if (!absolutePath.startsWith(`${uploadsRoot}${path.sep}`)) return res.status(400).json({ success: false, message: "Ruta de imagen no válida" });
    res.sendFile(absolutePath);
  } catch (error) {
    next(error);
  }
});

app.post("/api/form/datos-graficos", requireAuth, graphicUpload.fields(Object.keys(GRAPHIC_FIELDS).map((name) => ({ name, maxCount: 1 }))), async (req, res, next) => {
  const uploadedFiles = Object.values(req.files || {}).flat();
  const cleanTemporaryFiles = async () => Promise.all(uploadedFiles.map((file) => fsp.unlink(file.path).catch(() => {})));
  try {
    const acceptsPromotion = req.body.promocion_gtomx === "1" || req.body.promocion_gtomx === "true";
    if (!acceptsPromotion) {
      await cleanTemporaryFiles();
      return res.status(400).json({ success: false, message: "Debes aceptar la validación de la imagen promocional" });
    }
    for (const file of uploadedFiles) {
      const buffer = await fsp.readFile(file.path);
      const dimensions = getImageDimensions(buffer, file.mimetype);
      if (!dimensions) {
        await cleanTemporaryFiles();
        return res.status(400).json({ success: false, message: "Una imagen no coincide con el formato PNG o JPG" });
      }
      if (dimensions.width > 5000 || dimensions.height > 5000) {
        await cleanTemporaryFiles();
        return res.status(400).json({ success: false, message: "Las imágenes no deben superar 5000 × 5000 píxeles" });
      }
    }
    const [[current]] = await pool.execute(
      "SELECT imagen_promocional, logo, imagen1, imagen2 FROM ret_archivo_legal WHERE clave = ? LIMIT 1",
      [req.auth.clave],
    );
    if (!current) {
      await cleanTemporaryFiles();
      return res.status(404).json({ success: false, message: "No se encontró el expediente gráfico" });
    }
    const required = ["imagen_promocional", "logo", "imagen1", "imagen2"];
    if (required.some((field) => !current[field] && !req.files?.[field]?.[0])) {
      await cleanTemporaryFiles();
      return res.status(400).json({ success: false, message: "Adjunta todas las imágenes obligatorias" });
    }
    const graphicDirectory = path.join(uploadsRoot, "graphic", req.auth.clave);
    await fsp.mkdir(graphicDirectory, { recursive: true });
    const updates = [];
    const values = [];
    for (const [field, files] of Object.entries(req.files || {})) {
      const file = files[0];
      const extension = file.mimetype === "image/png" ? ".png" : ".jpg";
      const filename = `${field}-${crypto.randomUUID()}${extension}`;
      const destination = path.join(graphicDirectory, filename);
      await fsp.rename(file.path, destination);
      updates.push("?? = ?");
      values.push(GRAPHIC_FIELDS[field], path.relative(uploadsRoot, destination).replaceAll(path.sep, "/"));
    }
    if (updates.length) {
      await pool.query(`UPDATE ret_archivo_legal SET porcentaje_registro=60, promocion_gtomx=1, ${updates.join(", ")} WHERE clave=?`, [...values, req.auth.clave]);
    } else {
      await pool.execute("UPDATE ret_archivo_legal SET porcentaje_registro=60, promocion_gtomx=1 WHERE clave=?", [req.auth.clave]);
    }
    res.status(200).json({ success: true, message: "Documentación gráfica guardada correctamente" });
  } catch (error) {
    await cleanTemporaryFiles();
    next(error);
  }
});

const HOSPEDAJE_CHECKBOXES = Object.freeze([
  "cocineta", "cocinetaparcial", "aireacondicionado", "ventilador", "tv", "telefono",
  "minibar", "cable", "cajafuerte", "jacuzzi", "aguacaliente", "cafeteria", "restaurante",
  "cocinaindustrial", "banquete", "salon", "alberca", "chapoteadero", "area", "juego",
  "actividad", "bar", "boutique", "regalo", "tabaqueria", "internet", "sala", "gimnasio",
  "lavanderia", "tintoreria", "elevador", "acceso", "agencia", "spa", "room", "floreria",
  "arrendadora", "golf", "tenis", "ejecutivo", "estacionamiento",
]);
const HOSPEDAJE_ESTABLECIMIENTOS = Object.freeze(["Hotel", "Motel", "Resorts", "Hostal - Posada", "Albergue", "Amueblados", "Campamentos", "Trailer Parks", "Suites", "Villas", "Bungalows", "Casa de Huéspedes"]);
const HOSPEDAJE_TIPOS = Object.freeze(["Boutique", "Negocios", "Tradicional", "Tránsito", "Vacacional"]);
const HOSPEDAJE_TIPOS2 = Object.freeze(["Independiente", "Operadora"]);

app.get("/api/form/hospedaje", requireAuth, async (req, res, next) => {
  try {
    const [[business]] = await pool.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1", [req.auth.clave]);
    if (!business || Number(business.giro) !== 1) return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Hospedaje" });
    const [[row]] = await pool.execute("SELECT * FROM ret_frm_hospedaje WHERE clave = ? LIMIT 1", [req.auth.clave]);
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de hospedaje" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/hospedaje", requireAuth, async (req, res, next) => {
  const establecimiento = String(req.body.establecimiento || "").trim();
  const tipo = String(req.body.tipo || "").trim();
  const tipo2 = String(req.body.tipo2 || "").trim();
  const cuartos = Number.parseInt(req.body.cuartos, 10);
  const pisos = Number.parseInt(req.body.pisos, 10);
  const nocajon = req.body.nocajon === "" || req.body.nocajon == null ? null : Number.parseInt(req.body.nocajon, 10);
  const tipocajon = String(req.body.tipocajon || "").trim();
  const seguro = Number.parseInt(req.body.seguro, 10);
  const aseguradora = String(req.body.aseguradora || "").trim();
  const unidad = req.body.unidad === "" || req.body.unidad == null ? null : Number.parseInt(req.body.unidad, 10);
  if (!HOSPEDAJE_ESTABLECIMIENTOS.includes(establecimiento) || !HOSPEDAJE_TIPOS.includes(tipo) || !HOSPEDAJE_TIPOS2.includes(tipo2)) {
    return res.status(400).json({ success: false, message: "Selecciona las opciones obligatorias de hospedaje" });
  }
  if (![cuartos, pisos].every(Number.isInteger) || cuartos < 0 || pisos < 0 || cuartos > 999999 || pisos > 999) {
    return res.status(400).json({ success: false, message: "El número de habitaciones o pisos no es válido" });
  }
  if (![0, 1].includes(seguro) || (seguro === 1 && !aseguradora)) return res.status(400).json({ success: false, message: "Indica el seguro y la aseguradora" });
  if (nocajon !== null && (!Number.isInteger(nocajon) || nocajon < 0 || nocajon > 9999)) return res.status(400).json({ success: false, message: "El número de cajones no es válido" });
  if (tipocajon && !["Interno", "Externo"].includes(tipocajon)) return res.status(400).json({ success: false, message: "El tipo de estacionamiento no es válido" });
  if (unidad !== null && ![0, 1].includes(unidad)) return res.status(400).json({ success: false, message: "La opción de paraderos no es válida" });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 1) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Hospedaje" });
    }
    const checkboxAssignments = HOSPEDAJE_CHECKBOXES.map((field) => `\`${field}\` = ?`).join(", ");
    const checkboxValues = HOSPEDAJE_CHECKBOXES.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
    const [result] = await connection.execute(
      `UPDATE ret_frm_hospedaje SET establecimiento=?, tipo=?, tipo2=?, cuartos=?, pisos=?, ${checkboxAssignments}, nocajon=?, tipocajon=?, seguro=?, aseguradora=?, unidad=?, porcentaje_registro=80 WHERE clave=?`,
      [establecimiento, tipo, tipo2, cuartos, pisos, ...checkboxValues, nocajon, tipocajon || null, seguro, seguro ? aseguradora : null, unidad, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de hospedaje" });
    }
    await connection.execute("UPDATE ret_datos_generales SET porcentaje_registro=80 WHERE clave=?", [req.auth.clave]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de hospedaje guardado correctamente" });
  } catch (error) {
    await connection.rollback();
    next(error);
  } finally {
    connection.release();
  }
});

const AGENCIA_MODALIDADES = Object.freeze(["Minorista", "Emisora", "Receptora", "Operadores", "Mayorista", "Sub Agencias"]);
const AGENCIA_SEGMENTOS = Object.freeze(["Aventura y Naturaleza", "Turismo Cultural", "Turismo de Negocios", "Reuniones", "Historia y Cultura", "Historia", "Turismo Deportivo", "Salud", "Rural", "Gastronómico"]);

app.get("/api/form/agencia", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT a.modalidad, a.segmento, a.asociacion, a.nombre_asociacion, a.porcentaje_registro
       FROM ret_frm_agencia a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? AND d.giro = 2 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de agencia de viajes" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/agencia", requireAuth, async (req, res, next) => {
  const modalidad = String(req.body.modalidad || "").trim();
  const segmento = String(req.body.segmento || "").trim();
  const asociacion = Number.parseInt(req.body.asociacion, 10);
  const nombreAsociacion = String(req.body.nombre_asociacion || "").trim();
  if (!AGENCIA_MODALIDADES.includes(modalidad)) return res.status(400).json({ success: false, message: "Selecciona una modalidad válida" });
  if (!AGENCIA_SEGMENTOS.includes(segmento)) return res.status(400).json({ success: false, message: "Selecciona un segmento válido" });
  if (![0, 1].includes(asociacion)) return res.status(400).json({ success: false, message: "Indica si perteneces a una asociación" });
  if (asociacion === 1 && (!nombreAsociacion || nombreAsociacion.length > 100)) {
    return res.status(400).json({ success: false, message: "Captura el nombre de la asociación" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute(
      "SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE",
      [req.auth.clave],
    );
    if (!business || Number(business.giro) !== 2) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Agencia de viajes" });
    }
    const [result] = await connection.execute(
      `UPDATE ret_frm_agencia
       SET modalidad = ?, segmento = ?, asociacion = ?, nombre_asociacion = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [modalidad, segmento, asociacion, asociacion ? nombreAsociacion : null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de agencia de viajes" });
    }
    await connection.execute(
      "UPDATE ret_datos_generales SET concluido = 1, renovar = 0, autoclasificacion = ?, porcentaje_registro = 80 WHERE clave = ?",
      [modalidad, req.auth.clave],
    );
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de agencia de viajes guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const GUIA_CLASIFICACIONES = Object.freeze([
  "Local", "General", "Naturaleza", "Guía Especializado en actividad específica",
  "Especializado en Actividades específicas de Naturaleza y/o Aventura", "Guía Especializado",
]);
const GUIA_TIPOS = Object.freeze(["tip_historia", "tip_arte", "tip_cultura", "tip_museos", "tip_religiosos", "tip_compras", "tip_aventura"]);
const GUIA_IDIOMAS = Object.freeze(["esp", "fra", "eng", "ita", "ale", "cor", "por"]);

app.get("/api/form/guia", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT g.guia, g.tip_historia, g.tip_arte, g.tip_cultura, g.tip_museos,
              g.tip_religiosos, g.tip_compras, g.tip_aventura, g.num_credencial,
              g.nombre_asociacion, g.esp, g.fra, g.eng, g.ita, g.ale, g.cor, g.por,
              g.otro_idioma, g.porcentaje_registro
       FROM ret_frm_guia g JOIN ret_datos_generales d ON d.clave = g.clave
       WHERE g.clave = ? AND d.giro = 3 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de guía de turistas" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/guia", requireAuth, async (req, res, next) => {
  const guia = String(req.body.guia || "").trim();
  const numCredencial = String(req.body.num_credencial || "").trim();
  const nombreAsociacion = String(req.body.nombre_asociacion || "").trim();
  const otroIdioma = String(req.body.otro_idioma || "").trim();
  const tipos = GUIA_TIPOS.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  const idiomas = GUIA_IDIOMAS.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  if (!GUIA_CLASIFICACIONES.includes(guia)) return res.status(400).json({ success: false, message: "Selecciona una clasificación de guía válida" });
  if (!numCredencial || numCredencial.length > 50) return res.status(400).json({ success: false, message: "Captura un número de credencial válido" });
  if (nombreAsociacion.length > 100) return res.status(400).json({ success: false, message: "El nombre de la asociación no debe superar 100 caracteres" });
  if (otroIdioma.length > 50) return res.status(400).json({ success: false, message: "El otro idioma no debe superar 50 caracteres" });
  if (!tipos.some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un tipo de recorrido" });
  if (!idiomas.some(Boolean) && !otroIdioma) return res.status(400).json({ success: false, message: "Selecciona o captura al menos un idioma" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 3) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Guías de turistas" });
    }
    const typeAssignments = GUIA_TIPOS.map((field) => `\`${field}\` = ?`).join(", ");
    const languageAssignments = GUIA_IDIOMAS.map((field) => `\`${field}\` = ?`).join(", ");
    const [result] = await connection.execute(
      `UPDATE ret_frm_guia SET guia = ?, ${typeAssignments}, num_credencial = ?, nombre_asociacion = ?,
              ${languageAssignments}, otro_idioma = ?, porcentaje_registro = 100 WHERE clave = ?`,
      [guia, ...tipos, numCredencial, nombreAsociacion || null, ...idiomas, otroIdioma || null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de guía de turistas" });
    }
    await connection.execute(
      "UPDATE ret_datos_generales SET concluido = 1, renovar = 0, autoclasificacion = ?, porcentaje_registro = 80 WHERE clave = ?",
      [guia, req.auth.clave],
    );
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de guía de turistas guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const PROMOTOR_ZONAS = Object.freeze(["Establecimiento", "Local", "Via", "Aventura"]);

app.get("/api/form/promotores", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT p.licencia, p.zona, p.convenio, p.txt_convenio, p.porcentaje_registro
       FROM ret_frm_promotores p JOIN ret_datos_generales d ON d.clave = p.clave
       WHERE p.clave = ? AND d.giro = 4 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de operador de eventos" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/promotores", requireAuth, async (req, res, next) => {
  const licencia = Number.parseInt(req.body.licencia, 10);
  const zona = String(req.body.zona || "").trim();
  const convenio = Number.parseInt(req.body.convenio, 10);
  const txtConvenio = String(req.body.txt_convenio || "").trim();
  if (![0, 1].includes(licencia)) return res.status(400).json({ success: false, message: "Indica si cuentas con licencia" });
  if (!PROMOTOR_ZONAS.includes(zona)) return res.status(400).json({ success: false, message: "Selecciona una zona válida" });
  if (![0, 1].includes(convenio)) return res.status(400).json({ success: false, message: "Indica si cuentas con convenio" });
  if (convenio === 1 && (!txtConvenio || txtConvenio.length > 50)) {
    return res.status(400).json({ success: false, message: "Captura la descripción del convenio" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 4) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Operador y organizador de eventos" });
    }
    const [result] = await connection.execute(
      `UPDATE ret_frm_promotores
       SET licencia = ?, zona = ?, convenio = ?, txt_convenio = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [licencia, zona, convenio, convenio ? txtConvenio : null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de operador de eventos" });
    }
    await connection.execute(
      "UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?",
      [req.auth.clave],
    );
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de operador de eventos guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const RESTAURANTE_TIPOS = Object.freeze(["Restaurante", "Cafeteria", "Bar/Cantina", "Bares y Cantinas", "Centro Nocturno"]);
const RESTAURANTE_COCINAS = Object.freeze(["Mexicana", "Internacional", "Otros", "Asiática", "Italiana", "Carnes", "Del Mar", "Del_Mar"]);
const RESTAURANTE_CHECKBOXES = Object.freeze(["hro_matutino", "hro_vespertino", "hro_diurno", "hro_nocturno", "op_mesa", "op_autoservicio", "op_buffete", "op_alacarta"]);

app.get("/api/form/restaurantes", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT r.licencia, r.num_licencia, r.permiso, r.tipo_servicio, r.num_bebidas,
              r.hro_matutino, r.hro_vespertino, r.hro_diurno, r.hro_nocturno,
              r.num_potenciales, r.num_mesas, r.op_mesa, r.op_autoservicio,
              r.op_buffete, r.op_alacarta, r.tipo_establecimiento, r.tipo_cocina,
              r.porcentaje_registro
       FROM ret_frm_restaurantes r JOIN ret_datos_generales d ON d.clave = r.clave
       WHERE r.clave = ? AND d.giro = 5 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de alimentos y bebidas" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/restaurantes", requireAuth, async (req, res, next) => {
  const licencia = String(req.body.licencia || "").trim();
  const numLicencia = String(req.body.num_licencia || "").trim();
  const permiso = String(req.body.permiso || "").trim();
  const tipoServicio = String(req.body.tipo_servicio ?? "").trim();
  const numBebidas = String(req.body.num_bebidas || "").trim();
  const numPotenciales = Number.parseInt(req.body.num_potenciales, 10);
  const numMesas = Number.parseInt(req.body.num_mesas, 10);
  const tipoEstablecimiento = String(req.body.tipo_establecimiento || "").trim();
  const tipoCocina = String(req.body.tipo_cocina || "").trim();
  const checkboxes = RESTAURANTE_CHECKBOXES.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  if (!["Si", "No"].includes(licencia)) return res.status(400).json({ success: false, message: "Indica si cuentas con licencia" });
  if (licencia === "Si" && (!numLicencia || numLicencia.length > 40)) return res.status(400).json({ success: false, message: "Captura el número de licencia" });
  if (!["Si", "No"].includes(permiso)) return res.status(400).json({ success: false, message: "Indica si cuentas con permiso" });
  if (!["0", "1", "2"].includes(tipoServicio)) return res.status(400).json({ success: false, message: "Selecciona un tipo de servicio válido" });
  if (permiso === "Si" && (!numBebidas || numBebidas.length > 40)) return res.status(400).json({ success: false, message: "Captura el número del permiso de bebidas" });
  if (![numPotenciales, numMesas].every((value) => Number.isInteger(value) && value >= 0 && value <= 32767)) return res.status(400).json({ success: false, message: "La capacidad o número de mesas no es válido" });
  if (!RESTAURANTE_TIPOS.includes(tipoEstablecimiento)) return res.status(400).json({ success: false, message: "Selecciona un tipo de establecimiento válido" });
  if (!RESTAURANTE_COCINAS.includes(tipoCocina)) return res.status(400).json({ success: false, message: "Selecciona un tipo de cocina válido" });
  if (!checkboxes.slice(0, 4).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un horario de operación" });
  if (!checkboxes.slice(4).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos una modalidad de servicio" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 5) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Servicios de alimentos y bebidas" });
    }
    const checkboxAssignments = RESTAURANTE_CHECKBOXES.map((field) => `\`${field}\` = ?`).join(", ");
    const [result] = await connection.execute(
      `UPDATE ret_frm_restaurantes SET licencia = ?, num_licencia = ?, permiso = ?, tipo_servicio = ?, num_bebidas = ?,
              ${checkboxAssignments}, num_potenciales = ?, num_mesas = ?, tipo_establecimiento = ?, tipo_cocina = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [licencia, licencia === "Si" ? numLicencia : null, permiso, tipoServicio, permiso === "Si" ? numBebidas : null,
        ...checkboxes, numPotenciales, numMesas, tipoEstablecimiento, tipoCocina, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de alimentos y bebidas" });
    }
    await connection.execute(
      "UPDATE ret_datos_generales SET concluido = 1, renovar = 0, autoclasificacion = ?, porcentaje_registro = 80 WHERE clave = ?",
      [tipoEstablecimiento, req.auth.clave],
    );
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de alimentos y bebidas guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const GOLF_CHECKBOXES = Object.freeze([
  "plano", "semiplano", "ondulado",
  "serv01", "serv02", "serv03", "serv04", "serv05", "serv06", "serv07", "serv08", "serv09",
  "tc01", "tc02", "tc03", "tc04", "tc05", "tc06",
]);

app.get("/api/form/golf", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT g.turistico, g.hoyos, g.par, g.longitud, g.carrito, g.privado,
              g.plano, g.semiplano, g.ondulado, g.disenado, g.fairways, g.greens,
              g.serv01, g.serv02, g.serv03, g.serv04, g.serv05, g.serv06,
              g.serv07, g.serv08, g.serv09, g.tc01, g.tc02, g.tc03, g.tc04,
              g.tc05, g.tc06, g.otra_tc, g.porcentaje_registro
       FROM ret_frm_golf g JOIN ret_datos_generales d ON d.clave = g.clave
       WHERE g.clave = ? AND d.giro = 6 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de campo de golf" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/golf", requireAuth, async (req, res, next) => {
  const turistico = String(req.body.turistico || "").trim();
  const carrito = String(req.body.carrito || "").trim();
  const privado = String(req.body.privado || "").trim();
  const hoyos = String(req.body.hoyos || "").trim();
  const par = String(req.body.par || "").trim();
  const longitud = String(req.body.longitud || "").trim();
  const disenado = String(req.body.disenado || "").trim();
  const fairways = String(req.body.fairways || "").trim();
  const greens = String(req.body.greens || "").trim();
  const otraTc = String(req.body.otra_tc || "").trim();
  const checkboxes = GOLF_CHECKBOXES.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  if (![turistico, carrito, privado].every((value) => ["Si", "No"].includes(value))) return res.status(400).json({ success: false, message: "Completa las opciones Sí/No del campo de golf" });
  if (!/^\d{1,3}$/.test(hoyos) || !/^\d{1,3}$/.test(par) || !/^\d{1,7}$/.test(longitud)) return res.status(400).json({ success: false, message: "Los hoyos, par o longitud no tienen un formato válido" });
  if (!disenado || disenado.length > 120 || !fairways || fairways.length > 120 || !greens || greens.length > 120) return res.status(400).json({ success: false, message: "Captura diseño, fairways y greens" });
  if (otraTc.length > 120) return res.status(400).json({ success: false, message: "El otro medio de pago no debe superar 120 caracteres" });
  if (!checkboxes.slice(0, 3).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un tipo de terreno" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 6) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Campos de golf" });
    }
    const checkboxAssignments = GOLF_CHECKBOXES.map((field) => `\`${field}\` = ?`).join(", ");
    const [result] = await connection.execute(
      `UPDATE ret_frm_golf SET turistico = ?, hoyos = ?, par = ?, longitud = ?, carrito = ?, privado = ?,
              ${checkboxAssignments}, disenado = ?, fairways = ?, greens = ?, otra_tc = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [turistico, hoyos, par, longitud, carrito, privado, ...checkboxes, disenado, fairways, greens, otraTc || null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de campo de golf" });
    }
    await connection.execute("UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?", [req.auth.clave]);
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de campo de golf guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const ARTE_TIPOS = Object.freeze(["tipo1", "tipo2", "tipo3", "tipo4"]);

app.get("/api/form/arte", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT a.tipo1, a.tipo2, a.tipo3, a.tipo4, a.descripcion, a.operacion, a.porcentaje_registro
       FROM ret_frm_arte a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? AND d.giro = 7 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de arte popular" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/arte", requireAuth, async (req, res, next) => {
  const tipos = ARTE_TIPOS.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  const descripcion = String(req.body.descripcion || "").trim();
  const operacion = String(req.body.operacion || "").trim();
  if (!tipos.some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un tipo de establecimiento" });
  if (!descripcion || descripcion.length > 5000) return res.status(400).json({ success: false, message: "Captura una descripción de hasta 5000 caracteres" });
  if (!["Temporal", "Permanentes"].includes(operacion)) return res.status(400).json({ success: false, message: "Selecciona una modalidad de operación válida" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 7) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Establecimientos de arte popular y productos" });
    }
    const [result] = await connection.execute(
      `UPDATE ret_frm_arte
       SET tipo1 = ?, tipo2 = ?, tipo3 = ?, tipo4 = ?, descripcion = ?, operacion = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [...tipos, descripcion, operacion, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de arte popular" });
    }
    await connection.execute("UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?", [req.auth.clave]);
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de arte popular guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const ARRENDADORA_PERMISOS = Object.freeze(["perm1", "perm2", "perm3"]);
const ARRENDADORA_CARACTERISTICAS = Object.freeze(Array.from({ length: 14 }, (_, index) => `caract${index + 1}`));
const ARRENDADORA_MODALIDADES = Object.freeze(Array.from({ length: 5 }, (_, index) => `mod${String(index + 1).padStart(2, "0")}`));
const ARRENDADORA_SERVICIOS = Object.freeze(Array.from({ length: 12 }, (_, index) => `serv${String(index + 1).padStart(2, "0")}`));
const ARRENDADORA_PAGOS = Object.freeze(Array.from({ length: 6 }, (_, index) => `tc${String(index + 1).padStart(2, "0")}`));
const ARRENDADORA_CHECKBOXES = Object.freeze([...ARRENDADORA_PERMISOS, ...ARRENDADORA_CARACTERISTICAS, ...ARRENDADORA_MODALIDADES, ...ARRENDADORA_SERVICIOS, ...ARRENDADORA_PAGOS]);

app.get("/api/form/arrendadora", requireAuth, async (req, res, next) => {
  try {
    const checkboxColumns = ARRENDADORA_CHECKBOXES.map((field) => `a.\`${field}\``).join(", ");
    const [[row]] = await pool.query(
      `SELECT ${checkboxColumns}, a.novehiculos, a.tipovehiculos, a.capavehiculos, a.otra_tc, a.porcentaje_registro
       FROM ret_frm_arrendadora a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? AND d.giro = 9 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de arrendamiento de autos" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/arrendadora", requireAuth, async (req, res, next) => {
  const noVehiculos = String(req.body.novehiculos || "").trim();
  const tipoVehiculos = String(req.body.tipovehiculos || "").trim();
  const capaVehiculos = String(req.body.capavehiculos || "").trim();
  const otraTc = String(req.body.otra_tc || "").trim();
  const checkboxes = ARRENDADORA_CHECKBOXES.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  const offsetPermisos = ARRENDADORA_PERMISOS.length;
  const offsetCaracteristicas = offsetPermisos + ARRENDADORA_CARACTERISTICAS.length;
  const offsetModalidades = offsetCaracteristicas + ARRENDADORA_MODALIDADES.length;
  const offsetServicios = offsetModalidades + ARRENDADORA_SERVICIOS.length;
  if (!/^\d{1,9}$/.test(noVehiculos) || Number(noVehiculos) < 1) return res.status(400).json({ success: false, message: "Captura un número de unidades válido" });
  if (!tipoVehiculos || tipoVehiculos.length > 120 || !capaVehiculos || capaVehiculos.length > 120) return res.status(400).json({ success: false, message: "Captura el tipo y capacidad de las unidades" });
  if (otraTc.length > 120) return res.status(400).json({ success: false, message: "La otra forma de pago no debe superar 120 caracteres" });
  if (!checkboxes.slice(0, offsetPermisos).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un permiso" });
  if (!checkboxes.slice(offsetPermisos, offsetCaracteristicas).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos una característica del servicio" });
  if (!checkboxes.slice(offsetCaracteristicas, offsetModalidades).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos una modalidad de transporte" });
  if (!checkboxes.slice(offsetModalidades, offsetServicios).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un tipo de unidad o servicio" });
  if (!checkboxes.slice(offsetServicios).some(Boolean) && !otraTc) return res.status(400).json({ success: false, message: "Selecciona o captura al menos una forma de pago" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 9) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Arrendamiento de autos" });
    }
    const checkboxAssignments = ARRENDADORA_CHECKBOXES.map((field) => `\`${field}\` = ?`).join(", ");
    const [result] = await connection.execute(
      `UPDATE ret_frm_arrendadora SET ${checkboxAssignments}, novehiculos = ?, tipovehiculos = ?, capavehiculos = ?, otra_tc = ?, porcentaje_registro = 100 WHERE clave = ?`,
      [...checkboxes, noVehiculos, tipoVehiculos, capaVehiculos, otraTc || null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de arrendamiento de autos" });
    }
    await connection.execute("UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?", [req.auth.clave]);
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de arrendamiento de autos guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const PARQUES_SERVICIOS = Object.freeze(Array.from({ length: 35 }, (_, index) => `serv${String(index + 1).padStart(2, "0")}`));
const PARQUES_PAGOS = Object.freeze(Array.from({ length: 6 }, (_, index) => `tc${String(index + 1).padStart(2, "0")}`));
const PARQUES_CHECKBOXES = Object.freeze([...PARQUES_SERVICIOS, ...PARQUES_PAGOS]);

app.get("/api/form/parques", requireAuth, async (req, res, next) => {
  try {
    const checkboxColumns = PARQUES_CHECKBOXES.map((field) => `p.\`${field}\``).join(", ");
    const [[row]] = await pool.query(
      `SELECT ${checkboxColumns}, p.capacidad, p.otra_tc, p.porcentaje_registro
       FROM ret_frm_parques p JOIN ret_datos_generales d ON d.clave = p.clave
       WHERE p.clave = ? AND d.giro = 10 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de espacios turísticos" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/parques", requireAuth, async (req, res, next) => {
  const capacidad = String(req.body.capacidad || "").trim();
  const otraTc = String(req.body.otra_tc || "").trim();
  const checkboxes = PARQUES_CHECKBOXES.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  if (!capacidad || capacidad.length > 10) return res.status(400).json({ success: false, message: "Captura una capacidad máxima de hasta 10 caracteres" });
  if (otraTc.length > 120) return res.status(400).json({ success: false, message: "La otra forma de pago no debe superar 120 caracteres" });
  if (!checkboxes.slice(0, PARQUES_SERVICIOS.length).some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un servicio adicional" });
  if (!checkboxes.slice(PARQUES_SERVICIOS.length).some(Boolean) && !otraTc) return res.status(400).json({ success: false, message: "Selecciona o captura al menos una forma de pago" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 10) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Empresas operadoras de espacios turísticos" });
    }
    const checkboxAssignments = PARQUES_CHECKBOXES.map((field) => `\`${field}\` = ?`).join(", ");
    const [result] = await connection.execute(
      `UPDATE ret_frm_parques SET ${checkboxAssignments}, capacidad = ?, otra_tc = ?, porcentaje_registro = 100 WHERE clave = ?`,
      [...checkboxes, capacidad, otraTc || null, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de espacios turísticos" });
    }
    await connection.execute("UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?", [req.auth.clave]);
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de espacios turísticos guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

const AUX_TURISTICO_TURNOS = Object.freeze(["hora01", "hora02", "hora03", "hora04"]);

app.get("/api/form/auxturistico", requireAuth, async (req, res, next) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT a.hora01, a.hora02, a.hora03, a.hora04, a.horario, a.porcentaje_registro
       FROM ret_frm_auxturistico a JOIN ret_datos_generales d ON d.clave = a.clave
       WHERE a.clave = ? AND d.giro = 11 LIMIT 1`,
      [req.auth.clave],
    );
    if (!row) return res.status(404).json({ success: false, message: "No se encontró el formulario de operador turístico" });
    res.status(200).json({ success: true, data: row });
  } catch (error) {
    next(error);
  }
});

app.put("/api/form/auxturistico", requireAuth, async (req, res, next) => {
  const turnos = AUX_TURISTICO_TURNOS.map((field) => Number(req.body[field]) === 1 ? 1 : 0);
  const horario = String(req.body.horario || "").trim();
  if (!turnos.some(Boolean)) return res.status(400).json({ success: false, message: "Selecciona al menos un turno de operación" });
  if (!horario || horario.length > 120) return res.status(400).json({ success: false, message: "Captura un horario de hasta 120 caracteres" });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[business]] = await connection.execute("SELECT giro FROM ret_datos_generales WHERE clave = ? LIMIT 1 FOR UPDATE", [req.auth.clave]);
    if (!business || Number(business.giro) !== 11) {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Este formulario corresponde únicamente al giro Operador turístico" });
    }
    const [result] = await connection.execute(
      `UPDATE ret_frm_auxturistico
       SET hora01 = ?, hora02 = ?, hora03 = ?, hora04 = ?, horario = ?, porcentaje_registro = 100
       WHERE clave = ?`,
      [...turnos, horario, req.auth.clave],
    );
    if (!result.affectedRows) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "No se encontró el formulario de operador turístico" });
    }
    await connection.execute("UPDATE ret_datos_generales SET concluido = 1, renovar = 0, porcentaje_registro = 80 WHERE clave = ?", [req.auth.clave]);
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 80 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(200).json({ success: true, message: "Formulario de operador turístico guardado correctamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

app.get("/api/giros", async (req, res, next) => {
  try {
    const [rows] = await pool.query("SELECT id_giro, giro, resumen FROM ret_giro ORDER BY id_giro");
    res.status(200).json({ success: true, data: rows });
  } catch (error) {
    next(error);
  }
});

app.get("/api/municipios", async (req, res, next) => {
  try {
    const [rows] = await pool.query(
      "SELECT id_municipio, municipio FROM ret_municipio ORDER BY municipio",
    );
    res.status(200).json({ success: true, data: rows });
  } catch (error) {
    next(error);
  }
});

const requireEstablecimientoToken = (req, res, next) => {
  const configuredToken = process.env.TOKEN_ESTABLECIMIENTO;
  const receivedToken = req.get("x-establecimiento-token");

  if (!configuredToken) {
    return res.status(503).json({
      success: false,
      message: "El servicio de establecimientos no está configurado",
    });
  }

  if (!receivedToken) {
    return res.status(401).json({ success: false, message: "Acceso no autorizado" });
  }

  const configuredBuffer = Buffer.from(configuredToken);
  const receivedBuffer = Buffer.from(receivedToken);
  const isValid = configuredBuffer.length === receivedBuffer.length &&
    crypto.timingSafeEqual(configuredBuffer, receivedBuffer);

  if (!isValid) {
    return res.status(403).json({ success: false, message: "Acceso no autorizado" });
  }

  next();
};

const requireRegistrationAccess = (req, res, next) => {
  const token = req.cookies[SESSION_COOKIE];
  const secret = getJwtSecret();
  if (token && secret) {
    try {
      req.auth = jwt.verify(token, secret, { algorithms: ["HS256"], issuer: "ret-api", audience: "ret-web" });
      return next();
    } catch {
      res.clearCookie(SESSION_COOKIE, { path: "/" });
    }
  }
  return requireEstablecimientoToken(req, res, next);
};

const GIRO_TABLES = Object.freeze({
  1: "ret_frm_hospedaje",
  2: "ret_frm_agencia",
  3: "ret_frm_guia",
  4: "ret_frm_promotores",
  5: "ret_frm_restaurantes",
  6: "ret_frm_golf",
  7: "ret_frm_arte",
  8: "ret_frm_educativas",
  9: "ret_frm_arrendadora",
  10: "ret_frm_parques",
  11: "ret_frm_auxturistico",
  12: "ret_frm_balnearios",
  13: "ret_frm_capacitacion",
  14: "ret_frm_deporte",
  15: "ret_frm_spa",
  16: "ret_frm_recinto",
  17: "ret_frm_hospedaje-digitales",
  18: "ret_frm_etr",
  19: "ret_frm_intercambio",
});

const getMexicoDateParts = () => {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone: "America/Mexico_City",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hourCycle: "h23",
    }).formatToParts(new Date()).map(({ type, value }) => [type, value]),
  );
  const date = `${parts.year}-${parts.month}-${parts.day}`;
  return { date, dateTime: `${date} ${parts.hour}:${parts.minute}:${parts.second}` };
};

const generatePassword = () => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%";
  return Array.from({ length: 12 }, () => alphabet[crypto.randomInt(alphabet.length)]).join("");
};

app.post("/api/registro", requireRegistrationAccess, async (req, res, next) => {
  const rfc = String(req.body.rfc || "").trim().toUpperCase();
  const giro = Number.parseInt(req.body.giro, 10);
  const municipio = Number.parseInt(req.body.municipio, 10);
  const nombreComercial = String(req.body.nombre_completo || req.body.nombre_comercial || "").trim();
  const fechaInicio = String(req.body.fecha_inicio_operacion || req.body.fecha_inicio || "").trim();
  let correo = String(req.body.correo || req.body.email || "").trim().toLowerCase();
  const correoConfirmacion = String(req.body.correo_confirmacion || req.body.email_confirmation || "").trim().toLowerCase();
  const privacidad = req.body.privacidad === true || req.body.privacidad === 1 || req.body.privacidad === "1";

  if (!/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/.test(rfc)) {
    return res.status(400).json({ success: false, message: "El RFC no tiene un formato válido" });
  }
  if (!GIRO_TABLES[giro] || !Number.isInteger(municipio) || municipio < 1) {
    return res.status(400).json({ success: false, message: "El giro o municipio no es válido" });
  }
  if (!nombreComercial || nombreComercial.length > 200) {
    return res.status(400).json({ success: false, message: "El nombre comercial es obligatorio" });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fechaInicio) || Number.isNaN(Date.parse(`${fechaInicio}T00:00:00`))) {
    return res.status(400).json({ success: false, message: "La fecha de inicio no es válida" });
  }
  if (!req.auth && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo) || correo.length > 50 || correo !== correoConfirmacion)) {
    return res.status(400).json({ success: false, message: "Los correos no son válidos o no coinciden" });
  }
  if (!privacidad) {
    return res.status(400).json({ success: false, message: "Debes aceptar el aviso de privacidad" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    let inheritedPasswordHash = null;
    let inheritedProfile = 3;
    if (req.auth) {
      const [[owner]] = await connection.execute(
        "SELECT email, pass, id_perfil FROM ret_usr WHERE id_usr = ? AND id = ? AND activo = 1 LIMIT 1 FOR UPDATE",
        [req.auth.sub, req.auth.clave],
      );
      if (!owner) {
        await connection.rollback();
        return res.status(401).json({ success: false, message: "La sesión ya no es válida" });
      }
      correo = String(owner.email || "").trim().toLowerCase();
      inheritedPasswordHash = owner.pass;
      inheritedProfile = owner.id_perfil;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo) || correo.length > 150 || !inheritedPasswordHash) {
        await connection.rollback();
        return res.status(400).json({ success: false, message: "La cuenta actual no tiene un correo o acceso válido" });
      }
    }

    const [[municipioRow]] = await connection.execute(
      "SELECT id_municipio FROM ret_municipio WHERE id_municipio = ? LIMIT 1",
      [municipio],
    );
    if (!municipioRow) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: "El municipio seleccionado no existe" });
    }

    const [[existingRfc]] = await connection.execute(
      "SELECT id_pts FROM ret_datos_generales WHERE info_rfc = ? LIMIT 1",
      [rfc],
    );
    if (existingRfc) {
      await connection.rollback();
      return res.status(409).json({ success: false, message: "El RFC ya se encuentra registrado" });
    }

    const { date, dateTime } = getMexicoDateParts();
    const ipVisitante = String(req.ip || req.socket.remoteAddress || "").replace(/^::ffff:/, "").slice(0, 50);
    const [generalResult] = await connection.execute(
      `INSERT INTO ret_datos_generales
        (giro, municipio, nombre_comercial, info_rfc, correo, privacidad, ip_visitante, fecha, fecha_registro, fecha_inicio_operacion, porcentaje_registro, visible)
       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 10, 1)`,
      [giro, municipio, nombreComercial, rfc, correo, ipVisitante, date, dateTime, `${fechaInicio} 00:00:00`],
    );

    const idPts = generalResult.insertId;
    const clave = `RET${String(giro).padStart(2, "0")}${String(municipio).padStart(2, "0")}${String(idPts).padStart(4, "0")}`;
    await connection.execute("UPDATE ret_datos_generales SET clave = ? WHERE id_pts = ?", [clave, idPts]);
    await connection.execute("INSERT INTO ret_frm_tecnicos (clave) VALUES (?)", [clave]);
    await connection.execute("INSERT INTO ret_archivo_legal (clave) VALUES (?)", [clave]);

    const giroTable = GIRO_TABLES[giro];
    if (giro === 19) {
      await connection.query("INSERT INTO ?? (clave, nivel) VALUES (?, ?)", [giroTable, clave, "Pendiente"]);
    } else {
      await connection.query("INSERT INTO ?? (clave) VALUES (?)", [giroTable, clave]);
    }

    const temporaryPassword = req.auth ? null : generatePassword();
    const passwordHash = req.auth ? inheritedPasswordHash : await bcrypt.hash(temporaryPassword, 12);
    await connection.execute(
      `INSERT INTO ret_usr
        (activo, id, pass, email, privacidad, ip_visitante, id_perfil, fecha_registro, porcentaje_registro)
       VALUES (1, ?, ?, ?, 1, ?, ?, ?, 10)`,
      [clave, passwordHash, correo, ipVisitante, inheritedProfile, dateTime],
    );

    await connection.commit();
    if (req.auth) {
      return res.status(201).json({
        success: true,
        message: "El nuevo establecimiento fue agregado a tu cuenta",
        data: { clave, existingAccount: true, email: correo },
      });
    }
    let emailSent = false;
    try {
      await sendRegistrationCredentials({
        to: correo,
        clave,
        temporaryPassword,
        nombreComercial,
      });
      emailSent = true;
    } catch (mailError) {
      console.error("No fue posible enviar el correo de registro:", mailError.code || mailError.message);
    }
    res.status(201).json({
      success: true,
      message: emailSent
        ? "Registro creado correctamente. Enviamos las credenciales al correo indicado"
        : "Registro creado correctamente, pero no fue posible enviar el correo. Guarda las credenciales mostradas",
      data: { clave, temporaryPassword, emailSent },
    });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

app.post("/api/form/encuesta", requireAuth, async (req, res, next) => {
  const fueUtilidad = Number.parseInt(req.body.fue_utilidad, 10);
  const facilNavegacion = Number.parseInt(req.body.facil_navegacion, 10);
  const gustaria = String(req.body.gustaria || "").trim();
  if (![fueUtilidad, facilNavegacion].every((value) => Number.isInteger(value) && value >= 1 && value <= 5)) {
    return res.status(400).json({ success: false, message: "Selecciona una calificación de 1 a 5 estrellas en ambas preguntas" });
  }
  if (gustaria.length > 2000) {
    return res.status(400).json({ success: false, message: "La respuesta abierta no debe superar 2000 caracteres" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [[user]] = await connection.execute(
      `SELECT u.id_usr, d.giro FROM ret_usr u JOIN ret_datos_generales d ON d.clave = u.id
       WHERE u.id_usr = ? AND u.id = ? AND u.activo = 1 LIMIT 1 FOR UPDATE`,
      [req.auth.sub, req.auth.clave],
    );
    if (!user) {
      await connection.rollback();
      return res.status(401).json({ success: false, message: "La sesión ya no es válida" });
    }
    const { dateTime } = getMexicoDateParts();
    await connection.execute(
      "INSERT INTO ret_encuesta (fue_utilidad, facil_navegacion, gustaria, visible, fec_reg, usu_reg) VALUES (?, ?, ?, 1, ?, NULL)",
      [fueUtilidad, facilNavegacion, gustaria || null, dateTime],
    );
    if (Number(user.giro) === 8) {
      await connection.execute("UPDATE ret_datos_generales SET porcentaje_registro = 100, concluido = 1, renovar = 0 WHERE clave = ?", [req.auth.clave]);
    } else {
      await connection.execute("UPDATE ret_datos_generales SET porcentaje_registro = 100 WHERE clave = ?", [req.auth.clave]);
    }
    await connection.execute("UPDATE ret_usr SET porcentaje_registro = 100 WHERE id_usr = ?", [req.auth.sub]);
    await connection.commit();
    res.status(201).json({ success: true, message: "Gracias por compartir tu experiencia. Registro completado al 100%" });
  } catch (error) {
    if (connection) await connection.rollback();
    next(error);
  } finally {
    if (connection) connection.release();
  }
});

app.get("/api/establecimientos", requireEstablecimientoToken, async (req, res, next) => {
  try {
    const giro = Number.parseInt(req.query.giro || "1", 10);
    if (!Number.isInteger(giro) || giro < 1) {
      return res.status(400).json({ success: false, message: "El giro no es válido" });
    }
    const [rows] = await pool.execute(
      "SELECT nombre_comercial, latitud, longitud, descripcion FROM ret_datos_generales WHERE visible = 1 AND giro = ?",
      [giro],
    );
    const data = rows
      .map((row) => {
        const latitud = Number(row.latitud);
        const rawLongitud = Number(row.longitud);
        const longitud = rawLongitud > 0 ? -rawLongitud : rawLongitud;
        return { ...row, latitud, longitud };
      })
      .filter((row) =>
        Number.isFinite(row.latitud) &&
        Number.isFinite(row.longitud) &&
        row.latitud >= 14 && row.latitud <= 33 &&
        row.longitud >= -119 && row.longitud <= -86
      );
    res.status(200).json({ success: true, data });
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  console.error(error);
  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "Cada archivo debe pesar menos de 10 MB"
      : "No fue posible procesar los archivos adjuntos";
    return res.status(400).json({ success: false, message });
  }
  res.status(500).json({ success: false, message: "No fue posible procesar la solicitud" });
});

module.exports = app;
