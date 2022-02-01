// @ts-check
require('dotenv').config()
const bcryptjs = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const express = require('express');
const validator = require('validator').default;
const { UsersModel, sequelize } = require('./user.model');
const jwt = require('jsonwebtoken')
const app = express()
const port = process.env.PORT || 3000
app.use(express.json())

function verifyToken(req, res, next) {
  const token = req.headers.authorization
  if (token && token.length) {
    jwt.verify(token.replace(/bearer\s+/, ''), process.env.SECRET, (err, decodedToken) => {
      if (err) {
        return res.status(401).send({ status: 'Wrong token' })
      }
      req.user = { id: decodedToken.id }
      next()
    })
  } else {
    res.status(401).send({ status: 'Wrong token' })
  }
}

app.patch('/user', verifyToken, async (req, res) => {
  const { name, surname, birthday } = req.body
  const user = req.user
  await UsersModel.update({ name, surname, birthday }, { where: { id: user.id } })
  res.status(200).send({ status: 'success' })
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const userByEmail = await UsersModel.findOne({ where: { email } })
  if (userByEmail) {
    const plainedUser = userByEmail.get({ plain: true })
    if (await bcryptjs.compare(password, plainedUser.passwordHash)) {
      const token = jwt.sign({ id: plainedUser.id }, process.env.SECRET, { expiresIn: "2 days" })
      res.send({ token })
    } else {
      res.status(401).send({ status: 'Incorrect credentials' })
    }
  } else {
    res.status(401).send({ status: 'Incorrect credentials' })
  }
})

app.post('/signup',
  body('email').isEmail(),
  // (req, res, next) => {
  //   const { email } = req.body
  //   // if (email && /^\w+@\w+\.\w{1,3}$/.test(email)) {
  //   if (validator.isEmail(email)) {
  //     next()
  //   } else {
  //     res.status(400).send({ status: 'Incorrect email' })
  //   }
  // }, 
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, surname, birthday, email, password } = req.body
    try {
      const passwordHash = await bcryptjs.hash(password, 10)
      const userByEmail = await UsersModel.findOne({ where: { email } })
      if (!userByEmail) {
        const newUser = await UsersModel.create({ name, surname, birthday, email, passwordHash })
        res.status(201).send(newUser)
      } else {
        res.status(400).send({ message: 'This email is not unique' })
      }
    } catch (error) {
      console.error(error)
      res.status(500).send({ message: 'Server error' })
    }
  })

app.use((err, req, res, next) => {
  res.status(400).send(err)
})

async function start() {
  try {
    await sequelize.authenticate()
    await sequelize.sync()
    console.log('Successful db sync');
    app.listen(port)
  } catch (error) {
    console.error(error)
  }
}

start()