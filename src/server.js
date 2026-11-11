import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { PACKAGE_NAME, VERSION } from './config.js';
import {
  LOOKUP_DESCRIPTION,
  STAMP_DESCRIPTION,
  VERIFY_DESCRIPTION,
  formatToolResult,
  lookup,
  stamp,
  verify,
} from './tools.js';

export const TOOL_NAMES = ['stamp', 'verify', 'lookup'];

function asMcpResult(result) {
  return {
    content: [{ type: 'text', text: formatToolResult(result) }],
    isError: result && result.ok === false,
  };
}

export function createServer() {
  const server = new McpServer({
    name: PACKAGE_NAME,
    version: VERSION,
  });

  server.registerTool(
    'stamp',
    {
      title: 'Stamp with LightDrawer',
      description: STAMP_DESCRIPTION,
      inputSchema: {
        file: z.string().optional().describe('Local path of the file to hash. The file is read only to compute SHA-256 and is never uploaded.'),
        text: z.string().optional().describe('Text to hash as UTF-8. The text is hashed locally and never uploaded.'),
      },
    },
    async (args) => asMcpResult(await stamp(args)),
  );

  server.registerTool(
    'verify',
    {
      title: 'Verify a LightDrawer receipt',
      description: VERIFY_DESCRIPTION,
      inputSchema: {
        receipt: z.string().optional().describe('Local path to a LightDrawer receipt ZIP, or to a folder that contains statement.json.'),
        hash: z.string().optional().describe('SHA-256 hex of a stamped file or text. Looks for a locally saved original, and a saved receipt if one is in that folder.'),
        file: z.string().optional().describe('Optional local path of the original file, to check that it matches the receipt.'),
        text: z.string().optional().describe('Optional original text (UTF-8), to check that it matches the receipt.'),
      },
    },
    async (args) => asMcpResult(await verify(args)),
  );

  server.registerTool(
    'lookup',
    {
      title: 'Look up a LightDrawer stamp',
      description: LOOKUP_DESCRIPTION,
      inputSchema: {
        hash: z.string().optional().describe('64-character SHA-256 hex fingerprint to look up. For website-made receipts this is the hash of statement.json.'),
        file: z.string().optional().describe('Local file to hash, then look up that file hash.'),
        text: z.string().optional().describe('Text to hash (UTF-8), then look up that hash.'),
        receipt: z.string().optional().describe('Local receipt ZIP or folder. Looks up the SHA-256 of its statement.json.'),
      },
    },
    async (args) => asMcpResult(await lookup(args)),
  );

  return server;
}

export async function startServer() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  return server;
}
