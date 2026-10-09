const { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } = require("@aws-sdk/client-s3");

const S3_PREFIX = "RET2027";
let client;

const getConfig = () => {
  const bucket = String(process.env.AWS_BUCKET || "").trim();
  const region = String(process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "").trim();
  if (!bucket || !region || !process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
    throw new Error("La configuración de AWS S3 está incompleta en el backend");
  }
  if (!client) client = new S3Client({ region });
  return { bucket, client };
};

const validKey = (key) => typeof key === "string" && key.startsWith(`${S3_PREFIX}/`) && !key.includes("..") && key.length <= 512;

const putObject = async ({ key, body, contentType, filename }) => {
  if (!validKey(key)) throw new Error("La ruta S3 no es válida");
  const config = getConfig();
  await config.client.send(new PutObjectCommand({
    Bucket: config.bucket,
    Key: key,
    Body: body,
    ContentType: contentType,
    ContentDisposition: filename ? `attachment; filename="${String(filename).replace(/["\r\n]/g, "")}"` : undefined,
    ServerSideEncryption: "AES256",
  }));
  return key;
};

const getObject = async (key) => {
  if (!validKey(key)) throw new Error("La ruta S3 no es válida");
  const config = getConfig();
  return config.client.send(new GetObjectCommand({ Bucket: config.bucket, Key: key }));
};

const deleteObject = async (key) => {
  if (!validKey(key)) return;
  const config = getConfig();
  await config.client.send(new DeleteObjectCommand({ Bucket: config.bucket, Key: key }));
};

module.exports = { S3_PREFIX, validKey, putObject, getObject, deleteObject };
