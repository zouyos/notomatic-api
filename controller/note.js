const crypto = require('crypto');
const Note = require('../model/Note');

const algorithm = 'aes-256-ctr';

const secretKey = crypto
  .createHash('sha256')
  .update(process.env.ENCRYPTION_KEY)
  .digest();

function encryptContent(content) {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

  const encrypted = Buffer.concat([
    cipher.update(content, 'utf8'),
    cipher.final(),
  ]);

  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptContent(content) {
  const [ivHex, encryptedHex] = content.split(':');

  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);

  const decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

exports.create = async (req, res) => {
  try {
    const now = new Date();

    const note = new Note({
      title: req.body.title,
      content: encryptContent(req.body.content),
      userId: req.auth.userId,
      created_at: now,
      modified_at: now,
    });

    const savedNote = await note.save();

    const result = savedNote.toObject();
    result.content = decryptContent(result.content);

    res.status(201).json(result);
  } catch (err) {
    console.error('Error creating note:', err);
    res.status(400).json({ error: err.message });
  }
};

exports.getAll = async (req, res, next) => {
  try {
    const notes = await Note.find({ userId: req.auth.userId }).sort({
      modified_at: -1,
    });

    const decryptedNotes = notes.map((note) => ({
      ...note.toObject(),
      content: decryptContent(note.content),
    }));

    res.status(200).json(decryptedNotes);
  } catch (err) {
    res.status(400).json({ err });
  }
};

exports.getById = async (req, res) => {
  try {
    const note = await Note.findOne({
      _id: req.params.id,
      userId: req.auth.userId,
    });

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    const result = note.toObject();
    result.content = decryptContent(result.content);

    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.updateById = async (req, res) => {
  try {
    const updatedNote = await Note.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.auth.userId,
      },
      {
        title: req.body.title,
        content: encryptContent(req.body.content),
        modified_at: new Date(),
      },
      {
        new: true,
        runValidators: true,
      },
    );

    if (!updatedNote) {
      return res.status(404).json({ message: 'Note not found' });
    }

    const result = updatedNote.toObject();
    result.content = decryptContent(result.content);

    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.deleteById = async (req, res) => {
  try {
    const deletedNote = await Note.findOneAndDelete({
      _id: req.params.id,
      userId: req.auth.userId,
    });

    if (!deletedNote) {
      return res.status(404).json({ message: 'Note not found' });
    }

    res.status(200).json({ message: 'Note deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
