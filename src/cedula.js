const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const QRCode = require("qrcode");
const { PDFDocument, StandardFonts, rgb } = require("pdf-lib");

const templatePath = path.resolve(__dirname, "../assets/cedula-ret-template.pdf");
const navy = rgb(7 / 255, 55 / 255, 100 / 255);
const gray = rgb(58 / 255, 78 / 255, 87 / 255);

const createApprovalSeal = ({ clave, approvedAt }) => {
  const secret = String(process.env.APPROVAL_SEAL_SECRET || process.env.JWT_SECRET || "");
  if (secret.length < 32) throw new Error("APPROVAL_SEAL_SECRET o JWT_SECRET debe tener al menos 32 caracteres");
  const payload = `${clave}|${approvedAt}|${crypto.randomUUID()}`;
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${new Date(approvedAt).getTime()}.${signature}`;
};

const formatDate = (value) => {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return new Intl.DateTimeFormat("es-MX", { day: "2-digit", month: "long", year: "numeric" }).format(date);
};

const fitText = (font, text, maxWidth, initialSize = 11, minimumSize = 7) => {
  let size = initialSize;
  while (size > minimumSize && font.widthOfTextAtSize(text, size) > maxWidth) size -= 0.5;
  return size;
};

const drawValue = (page, font, value, x, y, width, size = 11) => {
  const text = String(value || "-").replace(/\s+/g, " ").trim();
  page.drawText(text, { x, y, size: fitText(font, text, width, size), font, color: navy, maxWidth: width });
};

const generateCedulaRet = async (record) => {
  const template = await fs.readFile(templatePath);
  const document = await PDFDocument.load(template);
  const page = document.getPage(0);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const approvalDate = record.fecha_aprobacion || new Date();
  const verificationBase = String(process.env.PUBLIC_API_URL || "http://localhost:3000").replace(/\/$/, "");
  const verificationUrl = `${verificationBase}/api/cedulas/verificar/${encodeURIComponent(record.cadena_aprobacion)}`;
  const qrData = await QRCode.toDataURL(verificationUrl, { errorCorrectionLevel: "M", margin: 1, width: 320 });
  const qrImage = await document.embedPng(qrData);

  drawValue(page, bold, record.nombre_comercial, 58, 616, 479, 18);
  drawValue(page, bold, record.clave, 58, 543, 479, 13);
  drawValue(page, regular, record.giro, 58, 485, 479, 12);
  drawValue(page, regular, record.domicilio, 58, 427, 479, 10.5);
  drawValue(page, regular, record.municipio, 58, 359, 230, 11);
  drawValue(page, regular, record.rfc, 330, 359, 207, 11);
  drawValue(page, regular, formatDate(record.fecha_registro), 58, 301, 230, 10.5);
  drawValue(page, regular, formatDate(approvalDate), 330, 301, 207, 10.5);
  page.drawImage(qrImage, { x: 58, y: 101, width: 112, height: 112 });
  page.drawText(record.cadena_aprobacion, { x: 212, y: 132, size: 6.3, font: regular, color: gray, maxWidth: 320, lineHeight: 8 });
  page.drawText("Validar en:", { x: 212, y: 112, size: 6.5, font: bold, color: navy });
  page.drawText(verificationUrl, { x: 252, y: 112, size: fitText(regular, verificationUrl, 280, 6.5, 5), font: regular, color: gray });

  document.setTitle(`Cédula RET ${record.clave}`);
  document.setSubject("Constancia de aprobación del Registro Estatal de Turismo");
  document.setAuthor("Registro Estatal de Turismo del Estado de Guanajuato");
  return Buffer.from(await document.save());
};

module.exports = { createApprovalSeal, generateCedulaRet };
