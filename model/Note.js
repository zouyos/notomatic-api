const mongoose = require('mongoose');

const noteSchema = mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  created_at: { type: Date, required: true, default: Date.now },
  modified_at: { type: Date, required: true, default: Date.now },
  userId: { type: String, required: true },
});

module.exports = mongoose.model('Note', noteSchema);
