// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Configuración de la base de datos PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'entrelineas',
  password: process.env.DB_PASSWORD || '123456',
  port: process.env.DB_PORT || 5432,
});

// Middleware
app.use(cors());
app.use(express.json());

// Servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Ruta raíz que redirige a Registro.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'Registro.html'));
});

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || '123456789';

// Crear tablas si no existen
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        apellidos VARCHAR(100),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        telefono VARCHAR(20),
        direccion TEXT,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activo BOOLEAN DEFAULT true
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS libros (
        id SERIAL PRIMARY KEY,
        titulo VARCHAR(255) NOT NULL,
        autor VARCHAR(255) NOT NULL,
        descripcion TEXT,
        categoria VARCHAR(100),
        precio NUMERIC(10, 2) NOT NULL,
        imagen TEXT,
        stock INTEGER DEFAULT 0,
        destacado BOOLEAN DEFAULT false,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_libros_titulo ON libros(titulo)`);

    console.log('Base de datos inicializada correctamente');
  } catch (error) {
    console.error('Error al inicializar la base de datos:', error);
  }
}

initializeDatabase();

// =================== Rutas de usuarios ===================

// Registro desde formulario HTML
app.post('/registrar', async (req, res) => {
  const { nombre, apellidos, email, password, telefono } = req.body;

  if (!nombre || !apellidos || !email || !password || !telefono) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  try {
    const existingUser = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO usuarios (nombre, apellidos, email, password, telefono)
       VALUES ($1, $2, $3, $4, $5)`,
      [nombre, apellidos, email.toLowerCase(), hashedPassword, telefono]
    );

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error('Error en /registrar:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1 AND activo = true', [email.toLowerCase()]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const usuario = result.rows[0];
    const passwordValida = await bcrypt.compare(password, usuario.password);

    if (!passwordValida) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, nombre: usuario.nombre },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await pool.query('UPDATE usuarios SET ultimo_acceso = CURRENT_TIMESTAMP WHERE id = $1', [usuario.id]);

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        telefono: usuario.telefono,
        direccion: usuario.direccion
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Registro con JWT (opcional)
app.post('/register', async (req, res) => {
  try {
    const { nombre, apellidos, email, password, telefono, direccion } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Nombre, email y contraseña son requeridos' });
    }

    const emailExists = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email.toLowerCase()]);
    if (emailExists.rows.length > 0) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellidos, email, password, telefono, direccion) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, nombre, email`,
      [nombre, apellidos, email.toLowerCase(), hashedPassword, telefono, direccion]
    );

    const nuevoUsuario = result.rows[0];

    const token = jwt.sign(
      { id: nuevoUsuario.id, email: nuevoUsuario.email, nombre: nuevoUsuario.nombre },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      token,
      user: nuevoUsuario
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Middleware de autenticación
const verificarToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

// Ruta protegida de perfil
app.get('/profile', verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, apellidos, email, telefono, direccion, fecha_registro FROM usuarios WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Error al obtener perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// =================== Rutas de libros ===================

// Crear libro (admin)
app.post('/libros', async (req, res) => {
  const { titulo, autor, descripcion, categoria, precio, imagen, stock, destacado } = req.body;

  if (!titulo || !autor || !precio || !imagen) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    await pool.query(
      `INSERT INTO libros (titulo, autor, descripcion, categoria, precio, imagen, stock, destacado)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [titulo, autor, descripcion || '', categoria || '', precio, imagen, stock || 0, destacado || false]
    );
    res.status(201).json({ message: 'Libro agregado correctamente' });
  } catch (error) {
    console.error('Error al agregar libro:', error);
    res.status(500).json({ error: 'Error al agregar libro' });
  }
});

// Eliminar libro
app.delete('/libros/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM libros WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Libro no encontrado' });
    }
    res.json({ message: 'Libro eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar libro:', error);
    res.status(500).json({ error: 'Error al eliminar libro' });
  }
});

// Obtener todos los libros
app.get('/libros', async (req, res) => {
  try {
    const resultado = await pool.query('SELECT * FROM libros ORDER BY fecha_creacion DESC');
    res.json(resultado.rows);
  } catch (error) {
    console.error('Error al obtener libros:', error);
    res.status(500).json({ error: 'Error al obtener libros' });
  }
});

// Obtener libro por ID
app.get('/libros/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM libros WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Libro no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener libro:', error);
    res.status(500).json({ error: 'Error al obtener libro' });
  }
});
// Actualizar libro
app.put('/libros/:id', async (req, res) => {
  const { id } = req.params;
  const { titulo, autor, descripcion, categoria, precio, imagen, stock, destacado } = req.body;

  if (!titulo || !autor || !precio || !imagen) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    const result = await pool.query(
      `UPDATE libros
       SET titulo = $1, autor = $2, descripcion = $3, categoria = $4, precio = $5, imagen = $6, stock = $7, destacado = $8
       WHERE id = $9`,
      [titulo, autor, descripcion || '', categoria || '', precio, imagen, stock || 0, destacado || false, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Libro no encontrado' });
    }

    res.json({ message: 'Libro actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar libro:', error);
    res.status(500).json({ error: 'Error al actualizar libro' });
  }
});
// Agregar libro al carrito
app.post('/carrito', async (req, res) => {
  const { usuario_id, libro_id, cantidad } = req.body;

  try {
    // Verificar si ya existe en el carrito
    const existing = await pool.query(
      'SELECT id, cantidad FROM carrito WHERE usuario_id = $1 AND libro_id = $2',
      [usuario_id, libro_id]
    );

    if (existing.rows.length > 0) {
      // Si ya existe, actualiza cantidad
      await pool.query(
        'UPDATE carrito SET cantidad = cantidad + $1 WHERE id = $2',
        [cantidad, existing.rows[0].id]
      );
    } else {
      // Si no existe, inserta nuevo
      await pool.query(
        'INSERT INTO carrito (usuario_id, libro_id, cantidad) VALUES ($1, $2, $3)',
        [usuario_id, libro_id, cantidad]
      );
    }

    res.json({ message: 'Libro agregado al carrito' });
  } catch (error) {
    console.error('Error al agregar al carrito:', error);
    res.status(500).json({ error: 'Error al agregar al carrito' });
  }
});

// Obtener carrito de un usuario
app.get('/carrito/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;

  try {
    const result = await pool.query(`
      SELECT c.id, c.cantidad, l.id AS libro_id, l.titulo, l.autor, l.precio, l.imagen
      FROM carrito c
      JOIN libros l ON c.libro_id = l.id
      WHERE c.usuario_id = $1
    `, [usuario_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener carrito:', error);
    res.status(500).json({ error: 'Error al obtener el carrito' });
  }
});

// Eliminar un libro del carrito
app.delete('/carrito/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query('DELETE FROM carrito WHERE id = $1', [id]);
    res.json({ message: 'Libro eliminado del carrito' });
  } catch (error) {
    console.error('Error al eliminar del carrito:', error);
    res.status(500).json({ error: 'Error al eliminar del carrito' });
  }
});
// Actualizar cantidad en el carrito
app.put('/carrito/:id', async (req, res) => {
  const { id } = req.params;
  const { cantidad } = req.body;

  try {
    await pool.query(
      'UPDATE carrito SET cantidad = $1 WHERE id = $2',
      [cantidad, id]
    );
    res.json({ message: 'Cantidad actualizada' });
  } catch (error) {
    console.error('Error al actualizar cantidad:', error);
    res.status(500).json({ error: 'Error al actualizar cantidad' });
  }
});
// Vaciar todo el carrito del usuario
app.delete('/carrito/usuario/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;

  try {
    await pool.query('DELETE FROM carrito WHERE usuario_id = $1', [usuario_id]);
    res.json({ message: 'Carrito vaciado correctamente' });
  } catch (error) {
    console.error('Error al vaciar carrito:', error);
    res.status(500).json({ error: 'Error al vaciar carrito' });
  }
});
app.put('/carrito/:id', async (req, res) => {
  const { id } = req.params;
  const { cantidad } = req.body;

  try {
    await pool.query('UPDATE carrito SET cantidad = $1 WHERE id = $2', [cantidad, id]);
    res.json({ message: 'Cantidad actualizada' });
  } catch (error) {
    console.error('Error al actualizar cantidad:', error);
    res.status(500).json({ error: 'Error al actualizar cantidad' });
  }
});
app.delete('/carrito/usuario/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;

  try {
    await pool.query('DELETE FROM carrito WHERE usuario_id = $1', [usuario_id]);
    res.json({ message: 'Carrito vaciado correctamente' });
  } catch (error) {
    console.error('Error al vaciar carrito:', error);
    res.status(500).json({ error: 'Error al vaciar carrito' });
  }
});
app.put('/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, email, telefono, direccion } = req.body;

  try {
    const result = await pool.query(
      `UPDATE usuarios 
       SET nombre = $1, email = $2, telefono = $3, direccion = $4
       WHERE id = $5`,
      [nombre, email, telefono, direccion, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ message: 'Perfil actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    res.status(500).json({ error: 'Error al actualizar el perfil' });
  }
});
app.post('/reportes', async (req, res) => {
  const { nombre, email, asunto, mensaje } = req.body;

  if (!nombre || !email || !asunto || !mensaje) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  try {
    await pool.query(
      'INSERT INTO reportes_soporte (nombre, email, asunto, mensaje) VALUES ($1, $2, $3, $4)',
      [nombre, email, asunto, mensaje]
    );

    res.status(201).json({ message: 'Reporte enviado correctamente' });
  } catch (error) {
    console.error('Error en /reportes:', error);
    res.status(500).json({ error: 'Error al enviar el reporte' });
  }
});

app.post('/crear-preferencia', async (req, res) => {
  const { usuario_id } = req.body;

  try {
    // Obtener los ítems del carrito del usuario
    const result = await pool.query(`
      SELECT l.titulo, l.precio, c.cantidad 
      FROM carrito c
      JOIN libros l ON c.libro_id = l.id
      WHERE c.usuario_id = $1
    `, [usuario_id]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Carrito vacío' });
    }

    const items = result.rows.map(item => ({
      title: item.titulo,
      unit_price: parseFloat(item.precio),
      quantity: item.cantidad,
      currency_id: 'COP'
    }));
    const preference = {
      items,
      back_urls: {
        success: 'http://localhost:5500/exito.html',
        failure: 'http://localhost:5500/error.html',
        pending: 'http://localhost:5500/pendiente.html'
      },
      auto_return: 'approved'
    };

    const response = await mercadopago.preferences.create(preference);
    res.json({ id: response.body.id });
  } catch (error) {
    console.error('Error al crear preferencia:', error);
    res.status(500).json({ error: 'No se pudo crear la preferencia' });
  }
});
app.get('/soporte', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reportes_soporte ORDER BY fecha DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener reportes de soporte:', error);
    res.status(500).json({ error: 'Error al obtener reportes' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo salió mal!' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
  console.log(`Health: http://localhost:${PORT}/health`);
});

// Cierre limpio
process.on('SIGINT', async () => {
  console.log('Cerrando servidor...');
  await pool.end();
  process.exit(0);
});
