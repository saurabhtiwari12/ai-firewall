'use strict';

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    username: { type: String },
    action: {
      type: String,
      required: true,
      enum: [
        'login',
        'logout',
        'register',
        'create_event',
        'update_event',
        'delete_event',
        'resolve_event',
        'create_alert',
        'update_alert',
        'delete_alert',
        'view_analytics',
        'admin_action',
      ],
    },
    resource: { type: String },
    resource_id: { type: String },
    ip: { type: String },
    user_agent: { type: String },
    status: { type: String, enum: ['success', 'failure'], default: 'success' },
    details: { type: mongoose.Schema.Types.Mixed },
  },
  {
    timestamps: { createdAt: 'timestamp', updatedAt: false },
    versionKey: false,
  }
);

auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ user: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;
