const mysql = require('mysql2/promise')
const pool = mysql.createPool({
  host: process.env.DB_HOST || process.env.HOST || 'localhost',
  port: Number(process.env.PORT_DB || process.env.DB_PORT || 3306),
  user: process.env.DB_USER || process.env.USUARIO || 'root',
  password: process.env.DB_PASSWORD || process.env.PASSWORD || '',
  database: process.env.DB_NAME || process.env.DATABASE || 'ret',
  waitForConnections: true,
  connectionLimit: 10,
})
module.exports = pool
