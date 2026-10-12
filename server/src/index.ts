import { buildApp, defaultConfig } from './app.js';

const config = defaultConfig();
const app = await buildApp(config);
const port = Number(process.env.PORT ?? 8080);
const host = process.env.HOST ?? '0.0.0.0';
await app.listen({ port, host });
app.log.info(`Obscura relay listening on http://${host}:${port} (data: ${config.dataDir})`);

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    void app.close().then(() => process.exit(0));
  });
}
