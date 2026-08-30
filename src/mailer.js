const nodemailer = require("nodemailer");

let transporter;

const getTransporter = () => {
  const host = String(process.env.MAIL_HOST || "").trim();
  const port = Number.parseInt(process.env.MAIL_PORT || "465", 10);
  const user = String(process.env.MAIL_USER || "").trim();
  const pass = String(process.env.MAIL_PASSWORD || "");
  if (!host || !Number.isInteger(port) || !user || !pass) {
    throw new Error("La configuración de correo está incompleta");
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host,
      port,
      secure: String(process.env.MAIL_SECURE || "").toLowerCase() === "true",
      auth: { user, pass },
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
      socketTimeout: 30_000,
    });
  }
  return transporter;
};

const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
})[character]);

const sendRegistrationCredentials = async ({ to, clave, temporaryPassword, nombreComercial }) => {
  const safeName = escapeHtml(nombreComercial);
  const safeClave = escapeHtml(clave);
  const safePassword = escapeHtml(temporaryPassword);
  return getTransporter().sendMail({
    from: process.env.MAIL_FROM || process.env.MAIL_USER,
    to,
    subject: "Credenciales de acceso al Registro Estatal de Turismo",
    text: `Hola ${nombreComercial},\n\nTu registro fue creado correctamente.\n\nClave RET: ${clave}\nContraseña temporal: ${temporaryPassword}\n\nPor seguridad, inicia sesión y resguarda tus credenciales.`,
    html: `
      <div style="margin:0;background:#edf8fb;padding:32px;font-family:Arial,sans-serif;color:#123d60">
        <div style="max-width:600px;margin:auto;border-radius:18px;background:#fff;overflow:hidden;box-shadow:0 12px 35px rgba(7,55,100,.16)">
          <div style="padding:24px 30px;background:linear-gradient(110deg,#00abc8,#0878b9);color:#fff">
            <strong style="font-size:22px">Registro Estatal de Turismo</strong>
            <div style="margin-top:5px;font-size:13px">Gobierno del Estado de Guanajuato</div>
          </div>
          <div style="padding:30px">
            <p style="margin-top:0">Hola <strong>${safeName}</strong>:</p>
            <p>Tu registro fue creado correctamente. Utiliza las siguientes credenciales para ingresar al sistema:</p>
            <div style="margin:24px 0;padding:18px;border:1px solid #b9dce5;border-radius:12px;background:#edf8fb">
              <div style="margin-bottom:12px;font-size:12px;color:#617887">CLAVE RET</div>
              <strong style="display:block;margin-bottom:20px;font-size:20px;color:#0b4a86">${safeClave}</strong>
              <div style="margin-bottom:12px;font-size:12px;color:#617887">CONTRASEÑA TEMPORAL</div>
              <strong style="display:block;font-size:20px;color:#0b4a86">${safePassword}</strong>
            </div>
            <p style="margin-bottom:0;font-size:13px;color:#617887">Por seguridad, resguarda estas credenciales y no las compartas.</p>
          </div>
        </div>
      </div>`,
  });
};

const sendPasswordRecovery = async ({ to, clave, temporaryPassword, nombreComercial }) => {
  const safeName = escapeHtml(nombreComercial || "usuario RET");
  const safeClave = escapeHtml(clave);
  const safePassword = escapeHtml(temporaryPassword);
  return getTransporter().sendMail({
    from: process.env.MAIL_FROM || process.env.MAIL_USER,
    to,
    subject: "Recuperación de acceso al Registro Estatal de Turismo",
    text: `Hola ${nombreComercial || "usuario RET"},\n\nRecibimos una solicitud para recuperar tu acceso.\n\nClave RET: ${clave}\nNueva contraseña temporal: ${temporaryPassword}\n\nSi no realizaste esta solicitud, contacta al soporte del RET.`,
    html: `
      <div style="margin:0;background:#edf8fb;padding:32px;font-family:Arial,sans-serif;color:#123d60">
        <div style="max-width:600px;margin:auto;border-radius:18px;background:#fff;overflow:hidden;box-shadow:0 12px 35px rgba(7,55,100,.16)">
          <div style="padding:24px 30px;background:linear-gradient(110deg,#00abc8,#0878b9);color:#fff">
            <strong style="font-size:22px">Recuperación de acceso RET</strong>
            <div style="margin-top:5px;font-size:13px">Registro Estatal de Turismo de Guanajuato</div>
          </div>
          <div style="padding:30px">
            <p style="margin-top:0">Hola <strong>${safeName}</strong>:</p>
            <p>Recibimos una solicitud para recuperar el acceso a tu cuenta. Tu nueva contraseña temporal es:</p>
            <div style="margin:24px 0;padding:18px;border:1px solid #b9dce5;border-radius:12px;background:#edf8fb">
              <div style="margin-bottom:8px;font-size:12px;color:#617887">CLAVE RET</div>
              <strong style="display:block;margin-bottom:18px;font-size:19px;color:#0b4a86">${safeClave}</strong>
              <div style="margin-bottom:8px;font-size:12px;color:#617887">NUEVA CONTRASEÑA TEMPORAL</div>
              <strong style="display:block;font-size:20px;color:#0b4a86">${safePassword}</strong>
            </div>
            <p style="font-size:13px;color:#617887">Si no realizaste esta solicitud, contacta al soporte del RET.</p>
          </div>
        </div>
      </div>`,
  });
};

module.exports = { sendRegistrationCredentials, sendPasswordRecovery };
