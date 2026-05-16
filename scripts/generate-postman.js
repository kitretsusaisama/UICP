/**
 * OpenAPI to Postman Collection Converter
 * Usage: node scripts/generate-postman.js
 */
const fs = require('fs');
const path = require('path');

const openapiPath = path.join(__dirname, '../openapi.json');
const outputPath = path.join(__dirname, '../UICP.postman_collection.json');

const openapi = JSON.parse(fs.readFileSync(openapiPath, 'utf8'));

// Extract info
const info = openapi.info || {};
const servers = openapi.servers || [];

// Group paths by first segment
const groups = {};
for (const [endpoint, methods] of Object.entries(openapi.paths)) {
  const segments = endpoint.split('/').filter(Boolean);
  const group = segments[0] || 'Other';
  if (!groups[group]) groups[group] = [];
  groups[group].push({ endpoint, methods });
}

// Build Postman collection
const collection = {
  info: {
    name: info.title || 'UICP API',
    description: info.description || 'Unified Identity and Communication Platform',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
  },
  variable: [
    {
      key: 'baseUrl',
      value: servers[0]?.url || 'http://localhost:3000',
      type: 'string'
    },
    {
      key: 'tenant-id',
      value: '',
      type: 'string'
    },
    {
      key: 'accessToken',
      value: '',
      type: 'string'
    }
  ],
  item: []
};

// Create items for each group
for (const [groupName, endpoints] of Object.entries(groups)) {
  const groupItem = {
    name: formatGroupName(groupName),
    item: []
  };

  for (const { endpoint, methods } of endpoints) {
    for (const [method, details] of Object.entries(methods)) {
      const request = {
        name: details.summary || `${method.toUpperCase()} ${endpoint}`,
        request: {
          method: method.toUpperCase(),
          header: [
            {
              key: 'Content-Type',
              value: 'application/json'
            },
            {
              key: 'x-tenant-id',
              value: '{{tenant-id}}',
              description: 'Tenant UUID required for tenant-scoped routes'
            },
            {
              key: 'Authorization',
              value: 'Bearer {{accessToken}}',
              description: 'JWT access token'
            }
          ],
          url: {
            raw: `{{baseUrl}}${endpoint}`,
            host: ['{{baseUrl}}'],
            path: endpoint.split('/').filter(Boolean)
          }
        }
      };

      // Add request body if present
      if (details.requestBody) {
        const content = details.requestBody.content?.['application/json'];
        if (content?.schema) {
          request.request.body = {
            mode: 'raw',
            raw: JSON.stringify(generateSampleBody(content.schema), null, 2),
            options: {
              raw: { language: 'json' }
            }
          };
        }
      }

      // Add response examples if available
      if (details.responses) {
        const responseExamples = [];
        for (const [status, response] of Object.entries(details.responses)) {
          const content = response.content?.['application/json'];
          if (content?.example) {
            responseExamples.push({
              name: `${status} Response`,
              status: status,
              code: parseInt(status),
              header: [{ key: 'Content-Type', value: 'application/json' }],
              body: JSON.stringify(content.example, null, 2)
            });
          }
        }
        if (responseExamples.length > 0) {
          request.request.response = responseExamples;
        }
      }

      groupItem.item.push(request);
    }
  }

  collection.item.push(groupItem);
}

function formatGroupName(name) {
  return name
    .replace(/^v\d+-/, '')
    .replace(/-/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

function generateSampleBody(schema, depth = 0) {
  if (depth > 3) return {};
  if (!schema) return {};

  if (schema.example) return schema.example;

  switch (schema.type) {
    case 'object':
      if (schema.properties) {
        const obj = {};
        for (const [key, prop] of Object.entries(schema.properties)) {
          obj[key] = generateSampleBody(prop, depth + 1);
        }
        return obj;
      }
      return {};
    case 'array':
      return [generateSampleBody(schema.items, depth + 1)];
    case 'string':
      return schema.format === 'uuid' ? '00000000-0000-0000-0000-000000000000' : 'string';
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return true;
    default:
      return 'sample';
  }
}

fs.writeFileSync(outputPath, JSON.stringify(collection, null, 2));
console.log(`Postman collection saved to: ${outputPath}`);
console.log(`Total endpoints: ${Object.keys(openapi.paths).length}`);