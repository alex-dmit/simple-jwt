const { Model, DataTypes } = require("sequelize");
const sequelize = require("./db");

class UsersModel extends Model { }

UsersModel.init({
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  surname: {
    type: DataTypes.STRING,
  },
  birthday: {
    type: DataTypes.DATE
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  sequelize,
  tableName: 'users'
})

module.exports = { UsersModel, sequelize }