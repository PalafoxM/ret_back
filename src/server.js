const path = require("path");
const envResult = require("dotenv").config({
  path: path.resolve(__dirname, "../.env"),
});

if (envResult.error) {
  throw new Error("No se pudo cargar el archivo .env del RET");
}

const app = require("./app");

const PORT = process.env.PORT || 3000;

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Servidor RET ejecutándose en http://localhost:${PORT}`);
});
