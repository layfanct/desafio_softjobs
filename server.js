import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import pkg from 'pg'
const { Pool } = pkg


// Cargar variables de entorno
dotenv.config()

const app = express()
const port = process.env.PORT || 3000
const SECRET_KEY = process.env.SECRET_KEY || 'softjobs_secret'

// Configuración de la base de datos
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'softjobs',
  password: process.env.DB_PASSWORD || '123456',
  port: process.env.DB_PORT || 5432,
})

// Middlewares
app.use(cors())
app.use(express.json())

// Middleware para registrar consultas en la terminal
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})

// Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(403).json({ message: 'Token requerido' })

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token inválido' })
    req.userEmail = decoded.email
    next()
  })
}

// Ruta para registrar un nuevo usuario
app.post('/usuarios', async (req, res) => {
    try {
      const { email, password, rol, lenguage } = req.body
  
      if (!email || !password || !rol || !lenguage) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' })
      }
  
      // Verificar si el email ya existe en la base de datos
      const existingUser = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
  
      if (existingUser.rows.length > 0) {
        return res.status(409).json({ message: 'Usuario ya existe' }) // 🔴 Error 409: Conflicto
      }
  
      // Encriptar la contraseña antes de guardarla
      const hashedPassword = await bcrypt.hash(password, 10)
  
      const result = await pool.query(
        'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING id, email, rol, lenguage',
        [email, hashedPassword, rol, lenguage]
      )
  
      res.status(201).json({ message: 'Usuario registrado con éxito', user: result.rows[0] })
    } catch (error) {
      console.error(error)
      res.status(500).json({ message: 'Error en el servidor' })
    }
  })
  

// Ruta para iniciar sesión y obtener un token JWT
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ message: 'Email y contraseña son obligatorios' })
    }

    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas' })
    }

    const user = result.rows[0]
    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Credenciales incorrectas' })
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' })

    res.status(200).json({ message: 'Inicio de sesión exitoso', token })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error en el servidor' })
  }
})

// Ruta protegida para obtener datos del usuario autenticado
app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT email, rol, lenguage FROM usuarios WHERE email = $1', [req.userEmail])
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' })
    }

    res.status(200).json(result.rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error en el servidor' })
  }
})

// Iniciar el servidor
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`)
})
