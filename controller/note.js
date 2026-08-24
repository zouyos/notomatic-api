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

exports.create = async (req, res, next) => {
  try {
    const noteObject = { ...req.body };

    delete noteObject.id;
    delete noteObject.userId;

    const encryptedContent = encryptContent(noteObject.content);

    const note = new Note({
      ...noteObject,
      content: encryptedContent,
      userId: req.auth.userId,
    });

    const savedNote = await note.save();

    savedNote.content = decryptContent(savedNote.content);

    res.status(201).json(savedNote);
  } catch (err) {
    console.error('Error creating note:', err);
    res.status(400).json({ error: err.message });
  }
};

exports.getAll = async (req, res, next) => {
  try {
    const notes = await Note.find({ userId: req.auth.userId });

    const decryptedNotes = notes.map((note) => ({
      ...note.toObject(),
      content: decryptContent(note.content),
    }));
    res.status(200).json(decryptedNotes);
  } catch (err) {
    res.status(400).json({ err });
  }
};

exports.getById = async (req, res, next) => {
  try {
    const note = await Note.findOne({ _id: req.params.id });

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    if (note.userId !== req.auth.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    note.content = decryptContent(note.content);
    res.status(200).json(note);
  } catch (error) {
    res.status(500).json({ error });
  }
};

exports.updateById = async (req, res, next) => {
  try {
    const noteObject = { ...req.body };

    delete noteObject.id;
    delete noteObject.userId;

    const note = await Note.findOne({ _id: req.params.id });

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    if (note.userId !== req.auth.userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const encryptedContent = encryptContent(noteObject.content);

    await Note.updateOne(
      { _id: req.params.id },
      {
        ...noteObject,
        content: encryptedContent,
        _id: req.params.id,
        userId: req.auth.userId,
      },
    );

    const updatedNote = await Note.findOne({ _id: req.params.id });

    updatedNote.content = decryptContent(updatedNote.content);

    res.status(200).json(updatedNote);
  } catch (error) {
    res.status(500).json({ error });
  }
};

exports.deleteById = (req, res, next) => {
  Note.findOne({ _id: req.params.id })
    .then((note) => {
      if (!note) {
        return res.status(404).json({ message: 'Note not found' });
      }

      if (note.userId !== req.auth.userId) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      return Note.deleteOne({ _id: req.params.id })
        .then(() => {
          res.status(200).json({ message: 'Note deleted' });
        })
        .catch((error) => res.status(500).json({ error }));
    })
    .catch((err) => res.status(400).json({ err }));
};
