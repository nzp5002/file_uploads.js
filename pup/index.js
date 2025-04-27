const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const shortid = require('shortid');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const argon2 = require('argon2');
const mime = require('mime-types');
const xss = require('xss');
const NodeClam = require('clamscan');

const app = express();
const PORT = 3000;
const uploadFolder = './uploads';
const EXPIRATION_HOURS = 46;
const MAX_FILE_SIZE = 20 * 1024 * 1024;
const MAX_DOWNLOADS = process.env.MAX_DOWNLOADS || 3;

if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);

mongoose.connect('mongodb://localhost:27017/file_uploads')
  .then(() => console.log('MongoDB conectado.'))
  .catch(err => {
    console.error('Erro ao conectar ao MongoDB:', err.message);
    process.exit(1);
  });

const fileSchema = new mongoose.Schema({
  original_name: String,
  saved_name: String,
  access_url: { type: String, unique: true },
  created_at: { type: Date, default: Date.now },
  passwordHash: String,
  iv: String,
  salt: String,
  downloads: { type: Number, default: 0 },
  attempts: { type: Number, default: 0 }
});

const File = mongoose.model('File', fileSchema);

const allowedExtensions = ['.png', '.jpg', '.jpeg', '.mp4',"webm","tar","zip","7z"];
const allowedMimeTypes = [
  'image/png', 'image/jpeg', 'application/pdf',
  'text/plain', 'video/mp4'
];

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;
  cb(null, allowedExtensions.includes(ext) && allowedMimeTypes.includes(mimeType));
};

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadFolder),
  filename: (_, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    cb(null, `${shortid.generate()}_${safeName}`);
  }
});

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function sanitizeInput(input) {
  return xss(input.replace(/[^a-zA-Z0-9\s]/g, ''));
}

function generateKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function generateSafeUrl() {
  return crypto.randomBytes(40).toString('hex').replace(/[^a-zA-Z0-9]/g, '');
}

function encryptFile(filePath, password, outputPath) {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(16);
  const key = generateKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  const input = fs.createReadStream(filePath);
  const output = fs.createWriteStream(outputPath);

  input.pipe(cipher).pipe(output);

  return new Promise((resolve, reject) => {
    output.on('finish', () => resolve({ iv: iv.toString('hex'), salt: salt.toString('hex') }));
    output.on('error', reject);
  });
}

function decryptAndSend(filePath, password, ivHex, saltHex, originalName, res) {
  const iv = Buffer.from(ivHex, 'hex');
  const salt = Buffer.from(saltHex, 'hex');
  const key = generateKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  const input = fs.createReadStream(filePath);

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);

  input.pipe(decipher).pipe(res).on('error', (err) => {
    console.error('Erro ao descriptografar/enviar o arquivo:', err);
    res.status(500).send('Erro ao enviar o arquivo.');
  });
}

// Iniciar ClamAV
let clamAV;
(async () => {
  try {
    const clamscan = await new NodeClam().init({
      removeInfected: false,
      quarantineInfected: false,
      scanRecursively: false,
      debugMode: false,
      clamscan: {
        path: '/usr/bin/clamscan', // ajuste conforme necessário
      },
      preference: 'clamscan'
    });
    clamAV = clamscan;
    console.log('ClamAV inicializado.');
  } catch (err) {
    console.error('Erro ao iniciar o ClamAV:', err.message);
    process.exit(1);
  }
})();

// Upload com verificação ANTES da criptografia
app.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });

    const { isInfected } = await clamAV.scanFile(req.file.path);
    if (isInfected) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Arquivo infectado por vírus.' });
    }

    const password = sanitizeInput(req.body.password);
    if (!password) return res.status(400).json({ error: 'Senha obrigatória.' });

    const passwordHash = await argon2.hash(password);
    const accessUrl = generateSafeUrl();
    const encryptedName = `enc_${req.file.filename}`;
    const encryptedPath = path.join(uploadFolder, encryptedName);

    const { iv, salt } = await encryptFile(req.file.path, password, encryptedPath);
    fs.unlinkSync(req.file.path);

    const file = new File({
      original_name: req.file.originalname,
      saved_name: encryptedName,
      access_url: accessUrl,
      passwordHash,
      iv,
      salt
    });

    await file.save();
    res.status(201).json({ url: `/file/${accessUrl}` });

  } catch (err) {
    console.error('Erro no upload:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Página de senha
app.get('/file/:accessUrl', async (req, res) => {
  try {
    const accessUrl = sanitizeInput(req.params.accessUrl);
    const file = await File.findOne({ access_url: accessUrl });
    if (!file) return res.status(404).send('Arquivo não encontrado.');

    res.send(`
    <!DOCTYPE HTML>
    <head lang="pt-br">
      <title>COLOQUE SUA SENHA</title>
      <meta charset="UTF-8">
      <style>

      /* Resetando margens e padding para garantir um layout consistente */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

/* Corpo da página */
body {
  font-family: 'Arial', sans-serif;
  background-color: #f4f7fc;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  flex-direction: column;
}

/* Título */
h2 {
  color: #333;
  margin-bottom: 20px;
  font-size: 24px;
  text-align: center;
}

/* Estilo do formulário */
form {
  display: flex;
  flex-direction: column;
  align-items: center;
  background: #fff;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
}

/* Estilo do input de senha */
input[type="password"] {
  width: 100%;
  padding: 12px;
  margin-bottom: 20px;
  border: 2px solid #ddd;
  border-radius: 8px;
  font-size: 16px;
  outline: none;
  transition: border-color 0.3s ease;
}

input[type="password"]:focus {
  border-color: #5c6bc0;
}

/* Estilo do botão de envio */
button {
  width: 100%;
  padding: 14px;
  background-color: #5c6bc0;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 18px;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

button:hover {
  background-color: #3f51b5;
}

button:active {
  background-color: #303f9f;
}

    </style>
    </head>
   <body>
      <h2>Download do arquivo: ${file.original_name}</h2>
      <form method="POST">
        <input type="password" name="password" placeholder="Digite a senha" required />
        <button type="submit">Baixar</button>
      </form>
   </body>
   </html>
    `);
  } catch (err) {
    res.status(500).send('Erro interno no servidor.');
  }
});

// Download com senha
app.post('/file/:accessUrl', async (req, res) => {
  try {
    const accessUrl = sanitizeInput(req.params.accessUrl);
    const password = sanitizeInput(req.body.password);
    const file = await File.findOne({ access_url: accessUrl });

    if (!file) return res.status(404).send('Arquivo não encontrado.');

    const valid = await argon2.verify(file.passwordHash, password);

    if (!valid) {
      file.attempts += 1;
      await file.save();

      if (file.attempts >= 2) {
        const filePath = path.join(uploadFolder, file.saved_name);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        await File.deleteOne({ _id: file._id });
        return res.status(403).send('Tentativas excedidas. Arquivo removido.');
      }

      return res.status(403).send(`Senha incorreta. Tentativas restantes: ${2 - file.attempts}`);
    }

    const expiration = new Date(file.created_at.getTime() + EXPIRATION_HOURS * 60 * 60 * 1000);
    if (new Date() > expiration) return res.status(410).send('Arquivo expirado.');

    if (file.downloads >= MAX_DOWNLOADS) return res.status(410).send('Limite máximo de download atingido.');

    const filePath = path.join(uploadFolder, file.saved_name);
    if (!fs.existsSync(filePath)) return res.status(410).send('Arquivo não encontrado no servidor.');

    file.downloads += 1;
    await file.save();

    decryptAndSend(filePath, password, file.iv, file.salt, file.original_name, res);

  } catch (err) {
    console.error('Erro no download:', err.message);
    res.status(500).send('Erro interno no servidor.');
  }
});

// Remoção de arquivos expirados (apenas limpeza, sem escaneamento)
setInterval(async () => {
  try {
    const now = new Date();
    const expirationLimit = new Date(now.getTime() - EXPIRATION_HOURS * 60 * 60 * 1000);
    const expiredFiles = await File.find({ created_at: { $lt: expirationLimit } });

    for (const file of expiredFiles) {
      const filePath = path.join(uploadFolder, file.saved_name);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      await File.deleteOne({ _id: file._id });
    }
  } catch (err) {
    console.error('[LIMPEZA] Erro:', err.message);
  }
}, 60 * 60 * 1000); // A cada 1 hora

app.use((_, res) => res.status(404).send('Página não encontrada.'));

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
