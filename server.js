import express from 'express';
import { SignJWT, importPKCS8 } from 'jose';

const app = express();
app.use(express.json());

// Endpoint 1: Generar JWT
app.post('/generate-jwt', async (req, res) => {
  try {
    const { sub, role, ...customClaims } = req.body;
    if (!sub) return res.status(400).json({ error: 'Missing sub' });

    const privateKey = await importPKCS8(process.env.JWT_PRIVATE_KEY, 'RS256');
    const jwt = await new SignJWT({ sub, role, ...customClaims })
      .setProtectedHeader({ alg: 'RS256', kid: 'mi-clave-001' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    res.json({ token: jwt });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Signing failed' });
  }
});

// Endpoint 2: Exponer JWKS (ruta estándar)
app.get('/.well-known/jwks', (req, res) => {
  const publicJwk = JSON.parse(process.env.JWT_PUBLIC_JWK);
  res.set('Content-Type', 'application/jwk-set+json');
  res.set('Cache-Control', 'public, max-age=3600');
  res.json({
    keys: [{
      kty: publicJwk.kty,
      use: 'sig',
      kid: 'mi-clave-001',
      alg: 'RS256',
      n: publicJwk.n,
      e: publicJwk.e,
    }],
  });
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
