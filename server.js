import express from 'express';
import { SignJWT, importPKCS8 } from 'jose';

const app = express();
app.use(express.json());

const jwt = require('jsonwebtoken');


// Variables de entorno (configuradas en Render)
// PRIVATE_KEY: clave privada PEM (con \n escapados o reales)
// KEY_ID: identificador de la clave (kid) que espera el servidor de autorización
const PRIVATE_KEY = process.env.PRIVATE_KEY
  ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
  : null;
const KEY_ID = process.env.KEY_ID;


// Endpoint 1: Generar JWT Assertion
app.post('/generate-assertion', (req, res) => {
  try {
    const { iss, sub, aud } = req.body;
    // Validación de parámetros y configuración
    if (!iss || !sub || !aud) {
      return res.status(400).json({
        error: 'Faltan parámetros requeridos: iss, sub, aud.'
      });
    }
    if (!PRIVATE_KEY || !KEY_ID) {
      return res.status(500).json({
        error: 'Configuración incompleta: faltan PRIVATE_KEY o KEY_ID en las variables de entorno.'
      });
    }

    // Timestamps calculados en el momento de la generación
    const now = Math.floor(Date.now() / 1000);
    const iat = now;
    // Vida útil máxima recomendada por CAMARA: 300 segundos
    const exp = now + 250;
    
    const payload = { iss, sub, aud, iat, exp };
    const token = jwt.sign(payload, PRIVATE_KEY, {
      algorithm: 'RS256',
      keyid: KEY_ID
    });
    res.json({ client_assertion: token });
  } catch (error) {
    console.error('Error generando JWT:', error);
    res.status(500).json({ error: 'Error interno al generar el JWT.' });
  }
});


// Endpoint 2: Exponer JWKS (ruta estándar)
app.get('/.well-known/jwks', (req, res) => {
  try {
    const raw = process.env.JWT_PUBLIC_JWK;
    if (!raw) {
      console.error('JWT_PUBLIC_JWK no está definida');
      return res.status(500).json({ error: 'JWKS no configurado' });
    }

    // Parseamos para validar que el JSON es correcto
    const jwks = JSON.parse(raw);

    // Validación mínima: debe tener un array "keys"
    if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
      console.error('JWT_PUBLIC_JWK no contiene un array "keys" válido');
      return res.status(500).json({ error: 'JWKS inválido' });
    }

    res.set('Content-Type', 'application/jwk-set+json');
    res.set('Cache-Control', 'public, max-age=3600');
    return res.status(200).json(jwks);
  } catch (err) {
    console.error('Error generando JWKS:', err);
    return res.status(500).json({ error: 'JWKS inválido' });
  }
});


// Endpoint 3: Solo endpoint de prueba de deployment
app.get('/test', (req, res) => {
  res.status(200);
  res.set('Content-Type', 'application/jwk-set+json');
  res.set('Cache-Control', 'public, max-age=3600');
  res.json({ message: 'Todo recibido OK' });
  // NADA después de res.json()
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
