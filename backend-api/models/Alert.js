'use strict';

const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, maxlength: 256 },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      required: true,
      index: true,
    },
    message: { type: String, required: true, maxlength: 2000 },
    source_ip: { type: String, index: true },
    event_count: { type: Number, default: 1, min: 1 },
    status: {
      type: String,
      enum: ['open', 'acknowledged', 'resolved', 'false_positive'],
      default: 'open',
      index: true,
    },
    related_events: [{ type: mongoose.Schema.Types.ObjectId, ref: 'SecurityEvent' }],
    acknowledged_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    acknowledged_at: { type: Date },
    resolved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    resolved_at: { type: Date },
    notes: { type: String, maxlength: 2000 },
  },
  {
    timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' },
    versionKey: false,
  }
);

alertSchema.index({ created_at: -1, severity: 1 });

const Alert = mongoose.model('Alert', alertSchema);

module.exports = Alert;
