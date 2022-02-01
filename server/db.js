const { Sequelize } = require('sequelize')

const dbHost = process.env.DB_HOST || 'localhost'
const dbPort = process.env.DB_PORT || '3306'

const dbName = process.env.DB_NAME || 'ov5_tasks_db'
const dbUser = process.env.DB_USER || 'ov5_tasks_user'
const dbPassword = process.env.DB_PASS || 'user12345'

const sequelize = new Sequelize(dbName, dbUser, dbPassword, {
  host: dbHost,
  port: parseInt(dbPort),
  dialect: 'mysql'
});

module.exports = sequelize