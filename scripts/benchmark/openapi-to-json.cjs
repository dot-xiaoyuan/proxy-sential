#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const modules = path.join(root, 'frontend/node_modules/.pnpm');
const installed = fs.readdirSync(modules).find(name => name.startsWith('js-yaml@'));
if (!installed) throw new Error('Run pnpm install in frontend first');
if (!process.argv[2]) throw new Error('Usage: node scripts/benchmark/openapi-to-json.cjs <output.json>');
const yaml = require(path.join(modules, installed, 'node_modules/js-yaml'));
fs.writeFileSync(process.argv[2], JSON.stringify(yaml.load(fs.readFileSync(path.join(root, 'schemas/control-plane-v1.openapi.yaml'), 'utf8'))));
