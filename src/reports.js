const writeXlsxFile = require("write-excel-file/node");

const STATE_REPORTS = Object.freeze({
  activos: { title: "Registros activos", where: "u.activo = 1" },
  pendientes: { title: "Trámites pendientes", where: "COALESCE(d.concluido, 0) = 0" },
  concluidos: { title: "Concluidos para validar", where: "d.concluido = 1 AND COALESCE(d.aprobado, 0) = 0 AND COALESCE(d.renovar, 0) = 0" },
  aprobados: { title: "Registros aprobados", where: "d.aprobado = 1" },
  renovaciones: { title: "Trámites en renovación", where: "d.renovar = 1" },
  vencidos: { title: "Registros vencidos", where: "u.fecha_renovacion IS NOT NULL AND u.fecha_renovacion <> '' AND COALESCE(STR_TO_DATE(u.fecha_renovacion, '%Y-%m-%d'), STR_TO_DATE(u.fecha_renovacion, '%d/%m/%Y')) < CURRENT_DATE()" },
});

const APP_REPORTS = Object.freeze({
  "app-hospedaje": { title: "App - Hospedaje", giro: 1, table: "ret_frm_hospedaje", alias: "f" },
  "app-plataformas-digitales": { title: "App - Plataformas digitales", giro: 17, table: "ret_frm_hospedaje-digitales", alias: "f" },
  "app-restaurantes": { title: "App - Restaurantes", giro: 5, table: "ret_frm_restaurantes", alias: "f" },
});

const safeCellValue = (value) => {
  if (value == null) return null;
  if (value instanceof Date || typeof value === "number" || typeof value === "boolean") return value;
  const text = String(value);
  return /^[=+\-@]/.test(text) ? `'${text}` : text;
};

const humanize = (field) => ({
  clave: "Clave RET", nombre_comercial: "Nombre comercial", giro: "Giro", municipio: "Municipio",
  correo: "Correo", fecha_registro: "Fecha de registro", porcentaje_registro: "Porcentaje de registro",
  concluido: "Concluido", aprobado: "Aprobado", renovar: "Renovación", visible: "Visible",
}[field] || field.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()));

const queryReport = async (pool, type) => {
  if (STATE_REPORTS[type]) {
    const config = STATE_REPORTS[type];
    const [rows] = await pool.query(`SELECT d.clave, d.nombre_comercial, g.giro, m.municipio,
      COALESCE(NULLIF(d.correo, ''), u.email) AS correo, d.info_rfc AS rfc,
      d.telefono, d.fecha_inicio_operacion, d.fecha_registro, d.porcentaje_registro,
      d.concluido, d.aprobado, d.renovar, d.visible, d.observaciones
      FROM ret_datos_generales d
      LEFT JOIN ret_usr u ON u.id = d.clave
      LEFT JOIN ret_giro g ON g.id_giro = d.giro
      LEFT JOIN ret_municipio m ON m.id_municipio = d.municipio
      WHERE ${config.where}
      ORDER BY d.fecha_registro DESC, d.id_pts DESC`);
    return { ...config, rows };
  }
  const config = APP_REPORTS[type];
  if (!config) return null;
  const [rows] = await pool.query(`SELECT d.clave, d.nombre_comercial, g.giro, m.municipio,
    COALESCE(NULLIF(d.correo, ''), u.email) AS correo, d.info_rfc AS rfc,
    d.telefono, d.fecha_inicio_operacion, d.fecha_registro, d.porcentaje_registro,
    d.concluido, d.aprobado, d.renovar, d.visible, ${config.alias}.*
    FROM ret_datos_generales d
    LEFT JOIN ret_usr u ON u.id = d.clave
    LEFT JOIN ret_giro g ON g.id_giro = d.giro
    LEFT JOIN ret_municipio m ON m.id_municipio = d.municipio
    LEFT JOIN ?? ${config.alias} ON ${config.alias}.clave = d.clave
    WHERE d.giro = ? ORDER BY d.fecha_registro DESC, d.id_pts DESC`, [config.table, config.giro]);
  return { ...config, rows };
};

const buildWorkbook = async ({ title, rows }) => {
  const fields = rows.length ? Object.keys(rows[0]).filter((field, index, all) => all.indexOf(field) === index) : ["clave", "nombre_comercial", "giro", "municipio", "correo"];
  const span = fields.length;
  const fillRow = (first) => [first, ...Array(Math.max(0, span - 1)).fill(null)];
  const sheetData = [
    fillRow({ value: title, columnSpan: span, height: 28, fontSize: 16, fontWeight: "bold", textColor: "#073764", alignVertical: "center" }),
    fillRow({ value: "Registro Estatal de Turismo del Estado de Guanajuato", columnSpan: span, fontSize: 10, textColor: "#617887" }),
    fillRow({ value: `Generado: ${new Intl.DateTimeFormat("es-MX", { dateStyle: "medium", timeStyle: "short", timeZone: "America/Mexico_City" }).format(new Date())}`, columnSpan: span, fontSize: 9, fontStyle: "italic", textColor: "#617887" }),
    fields.map((field) => ({ value: humanize(field), height: 28, backgroundColor: "#073764", textColor: "#FFFFFF", fontWeight: "bold", align: "center", alignVertical: "center", wrap: true, borderColor: "#D9E7EB", borderStyle: "thin" })),
    ...rows.map((row) => fields.map((field) => {
      const value = safeCellValue(row[field]);
      const cell = { value, height: 20, textColor: "#1F3440", alignVertical: "center", borderColor: "#E7EFF2", borderStyle: "thin" };
      if (value instanceof Date) cell.format = /fecha/.test(field) ? "dd/mm/yyyy hh:mm" : "dd/mm/yyyy";
      if (/porcentaje/.test(field) && typeof value === "number") cell.format = "0";
      return cell;
    })),
  ];
  const columns = fields.map((field) => {
    const maxLength = Math.max(humanize(field).length, ...rows.slice(0, 300).map((row) => String(row[field] ?? "").length));
    return { width: Math.min(Math.max(maxLength + 2, 12), 42) };
  });
  return writeXlsxFile(sheetData, {
    sheet: "Reporte",
    columns,
    stickyRowsCount: 4,
    showGridLines: false,
    orientation: fields.length > 8 ? "landscape" : "portrait",
    dateFormat: "dd/mm/yyyy",
  }, { fontFamily: "Arial", fontSize: 9 }).toBuffer();
};

module.exports = { STATE_REPORTS, APP_REPORTS, queryReport, buildWorkbook };
