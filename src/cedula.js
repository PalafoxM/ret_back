const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const QRCode = require("qrcode");
const { PDFDocument, StandardFonts, rgb } = require("pdf-lib");

const backgroundPath = path.resolve(__dirname, "../assets/cedula_2024-2030.png");
const navy = rgb(7 / 255, 55 / 255, 100 / 255);
const gray = rgb(58 / 255, 78 / 255, 87 / 255);
const pageWidth = 1064;
const pageHeight = 822;

const createApprovalSeal = ({ clave, approvedAt }) => {
  const secret = String(process.env.APPROVAL_SEAL_SECRET || process.env.JWT_SECRET || "");
  if (secret.length < 32) throw new Error("APPROVAL_SEAL_SECRET o JWT_SECRET debe tener al menos 32 caracteres");
  const payload = `${clave}|${approvedAt}|${crypto.randomUUID()}`;
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${new Date(approvedAt).getTime()}.${signature}`;
};

const parseDatabaseDate = (value) => {
  if (value instanceof Date) return new Date(value.getTime());
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (match) return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return new Date(value);
};

const formatDate = (value) => {
  if (!value) return "-";
  const date = parseDatabaseDate(value);
  if (Number.isNaN(date.getTime())) return "-";
  return new Intl.DateTimeFormat("es-MX", { day: "2-digit", month: "2-digit", year: "numeric" }).format(date);
};

const formatRegistrationDate = (value) => {
  const match = String(value || "").match(/^(\d{2}\/\d{2}\/\d{4})/);
  return match ? match[1] : formatDate(value);
};

const expirationDate = (value) => {
  const date = parseDatabaseDate(value);
  if (Number.isNaN(date.getTime())) return null;
  date.setFullYear(date.getFullYear() + 3);
  return date;
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

const drawCenteredValue = (page, font, value, x, y, width, size = 11) => {
  const text = String(value || "-").replace(/\s+/g, " ").trim();
  const fittedSize = fitText(font, text, width, size);
  const textWidth = font.widthOfTextAtSize(text, fittedSize);
  page.drawText(text, { x: x + Math.max(0, (width - textWidth) / 2), y, size: fittedSize, font, color: navy });
};

const generateCedulaRet = async (record) => {
  const verificationUrl = String(record.verificationUrl || "").trim();
  if (!/^https?:\/\/[^\s]+$/i.test(verificationUrl)) throw new Error("La URL pública de verificación de la Cédula RET no está configurada");
  const backgroundBytes = await fs.readFile(backgroundPath);
  const document = await PDFDocument.create();
  const page = document.addPage([pageWidth, pageHeight]);
  const background = await document.embedPng(backgroundBytes);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const qrData = await QRCode.toDataURL(verificationUrl, { errorCorrectionLevel: "M", margin: 1, width: 320 });
  const qrImage = await document.embedPng(qrData);

  page.drawImage(background, { x: 0, y: 0, width: pageWidth, height: pageHeight });
  drawCenteredValue(page, bold, record.clave, 700, 618, 320, 27);
  drawValue(page, bold, record.nombre_comercial, 310, 492, 700, 27);
  drawValue(page, regular, record.rfc ? `RFC: ${record.rfc}` : "", 310, 461, 700, 15);
  drawValue(page, bold, record.domicilio, 310, 428, 700, 16);
  drawValue(page, regular, record.municipio, 310, 400, 700, 15);
  drawValue(page, bold, record.giro, 300, 278, 700, 20);
  drawValue(page, bold, formatRegistrationDate(record.fecha_inscripcion), 300, 226, 230, 18);
  drawValue(page, bold, formatDate(expirationDate(record.fecha_vigencia_base)), 300, 194, 230, 18);
  page.drawImage(qrImage, { x: 885, y: 86, width: 135, height: 135 });
  const seal = String(record.cadena_aprobacion || "");
  page.drawText("SELLO DIGITAL", { x: 590, y: 105, size: 7, font: bold, color: gray });
  page.drawText(seal.slice(0, 48), { x: 590, y: 91, size: 5.1, font: regular, color: gray });
  page.drawText(seal.slice(48), { x: 590, y: 82, size: 5.1, font: regular, color: gray });

  document.setTitle(`Cédula RET ${record.clave}`);
  document.setSubject("Constancia de aprobación del Registro Estatal de Turismo");
  document.setAuthor("Registro Estatal de Turismo del Estado de Guanajuato");
  return Buffer.from(await document.save());
};

module.exports = { createApprovalSeal, generateCedulaRet };
