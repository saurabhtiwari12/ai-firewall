'use strict';

const mongoose = require('mongoose');

const geoLocationSchema = new mongoose.Schema(
  {
    country: { type: String, default: '' },
    country_code: { type: String, default: '' },
    city: { type: String, default: '' },
    latitude: { type: Number },
    longitude: { type: Number },
  },
  { _id: false }
);

const flowFeaturesSchema = new mongoose.Schema(
  {
    packet_count: { type: Number, default: 0 },
    byte_count: { type: Number, default: 0 },
    duration_ms: { type: Number, default: 0 },
    avg_packet_size: { type: Number, default: 0 },
    flags: { type: [String], default: [] },
    inter_arrival_time_ms: { type: Number, default: 0 },
  },
  { _id: false }
);

const securityEventSchema = new mongoose.Schema(
  {
    // Network identifiers
    src_ip: { type: String, required: true, index: true },
    dst_ip: { type: String, required: true },
    src_port: { type: Number, min: 0, max: 65535 },
    dst_port: { type: Number, min: 0, max: 65535 },
    protocol: {
      type: String,
      enum: ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'OTHER'],
      default: 'TCP',
    },

    // Threat classification
    threat_score: { type: Number, min: 0, max: 1, required: true, index: true },
    risk_level: {
      type: String,
      enum: ['safe', 'suspicious', 'high', 'critical'],
      required: true,
      index: true,
    },
    attack_type: {
      type: String,
      enum: [
        'port_scan',
        'brute_force',
        'sql_injection',
        'xss',
        'ddos',
        'malware',
        'ransomware',
        'data_exfiltration',
        'man_in_the_middle',
        'zero_day',
        'normal',
        'unknown',
      ],
      default: 'unknown',
    },
    action_taken: {
      type: String,
      enum: ['allow', 'block', 'monitor', 'quarantine'],
      default: 'monitor',
    },

    // AI scoring
    ai_score: { type: Number, min: 0, max: 1, default: 0 },
    anomaly_score: { type: Number, min: 0, max: 1, default: 0 },
    behavioral_score: { type: Number, min: 0, max: 1, default: 0 },

    // Enrichment
    flow_features: { type: flowFeaturesSchema, default: () => ({}) },
    geo_location: { type: geoLocationSchema, default: () => ({}) },

    // Resolution
    resolved: { type: Boolean, default: false, index: true },
    resolved_at: { type: Date },
    resolved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    notes: { type: String, maxlength: 2000 },
  },
  {
    timestamps: { createdAt: 'timestamp', updatedAt: 'updated_at' },
    versionKey: false,
  }
);

// Compound indexes for common query patterns
securityEventSchema.index({ timestamp: -1, risk_level: 1 });
securityEventSchema.index({ src_ip: 1, timestamp: -1 });
securityEventSchema.index({ attack_type: 1, timestamp: -1 });

const SecurityEvent = mongoose.model('SecurityEvent', securityEventSchema);

module.exports = SecurityEvent;
