require("dotenv").config();
const fs = require("fs/promises");
const path = require("path");
const { createApprovalSeal, generateCedulaRet } = require("../src/cedula");

async function main() {
  const approvedAt = new Date();
  const record = {
    clave: "RET01010023",
    nombre_comercial: "Hotel Ejemplo Guanajuato",
    giro: "01. Hospedaje",
    domicilio: "Calle Principal 123, Centro, C.P. 36000",
    municipio: "Guanajuato",
    rfc: "EJEM010203AB4",
    fecha_registro: "2026-10-01T12:00:00",
    fecha_aprobacion: approvedAt,
  };
  record.cadena_aprobacion = createApprovalSeal({ clave: record.clave, approvedAt: approvedAt.toISOString() });
  const pdf = await generateCedulaRet(record);
  const outputDirectory = path.resolve(__dirname, "../output/pdf");
  await fs.mkdir(outputDirectory, { recursive: true });
  const output = path.join(outputDirectory, "cedula-ret-preview.pdf");
  await fs.writeFile(output, pdf);
  console.log(output);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
