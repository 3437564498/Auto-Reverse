import { createServer, type Server, type Socket } from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import { chmod, lstat, mkdir, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { ProfileReport, RecoveryHost } from './contracts.js';
import type { PythonDomainClient } from './python-domain-client.js';

/** Host-only capability transport. No tool registration, SDK request extension or secret logging. */
export class AuthenticatedLocalHost implements RecoveryHost {
  private readonly roots = new Map<string, { job_id: string; batch_ref: string }>();
  private readonly sockets = new Set<Socket>();
  private handler: ((jobId: string) => Promise<void>) | undefined;
  private server: Server | undefined;
  private ready = false;
  private readonly path: string;
  constructor(socketPath: string, private readonly secret: string, private readonly domain: PythonDomainClient, private readonly profile: () => Promise<ProfileReport>) {
    this.path = resolve(socketPath);
    if (Buffer.byteLength(secret) < 32 || Buffer.byteLength(secret) > 1024) throw new Error('CONTROL_SECRET_TOO_SHORT');
  }
  isAuthenticated(): boolean { return this.ready; }
  async listen(): Promise<void> {
    if (process.platform === 'win32') throw new Error('UNIX_CONTROL_REQUIRED');
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) throw new Error('UNSAFE_CONTROL_DIRECTORY');
    try { await lstat(this.path); throw new Error('CONTROL_SOCKET_ALREADY_EXISTS'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    this.server = createServer(socket => this.connection(socket));
    this.server.on('error', () => { this.ready = false; });
    await new Promise<void>((yes, no) => { this.server!.once('error', no); this.server!.listen(this.path, () => { this.server!.removeListener('error', no); yes(); }); });
    await chmod(this.path, 0o600);
    this.ready = true;
  }
  private connection(socket: Socket): void {
    this.sockets.add(socket); socket.setTimeout(10_000, () => socket.destroy());
    socket.on('error', () => socket.destroy()); socket.on('close', () => this.sockets.delete(socket));
    let buffer = ''; let busy = false;
    socket.setEncoding('utf8');
    socket.on('data', chunk => {
      if (busy) { socket.destroy(); return; }
      buffer += String(chunk);
      if (Buffer.byteLength(buffer) > 64 * 1024) { socket.destroy(); return; }
      const newline = buffer.indexOf('\n'); if (newline < 0) return;
      busy = true;
      if (buffer.slice(newline + 1).trim()) { socket.destroy(); return; }
      void this.handle(buffer.slice(0, newline)).then(result => socket.end(JSON.stringify({ result }) + '\n'), () => socket.end(JSON.stringify({ error: { code: 'CONTROL_REJECTED' } }) + '\n'));
    });
  }
  private async handle(line: string): Promise<unknown> {
    const request = JSON.parse(line) as { token?: unknown; method?: unknown; params?: Record<string, unknown> };
    if (typeof request.token !== 'string') throw new Error('UNAUTHORIZED');
    const provided = Buffer.from(request.token); const expected = Buffer.from(this.secret);
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) throw new Error('UNAUTHORIZED');
    const params = request.params ?? {};
    if (request.method === 'preflight') return this.profile();
    if (request.method === 'authorize_root') {
      if (typeof params.session_id !== 'string' || !params.session_id || typeof params.batch_ref !== 'string' || typeof params.job_id !== 'string') throw new Error('INVALID_ROOT_AUTHORIZATION');
      const plan = await this.domain.loadBatch(params.batch_ref);
      if (plan.job_id !== params.job_id) throw new Error('BATCH_JOB_MISMATCH');
      const existing = this.roots.get(params.session_id);
      if (existing !== undefined && (existing.job_id !== params.job_id || existing.batch_ref !== params.batch_ref)) throw new Error('ROOT_ALREADY_AUTHORIZED');
      this.roots.set(params.session_id, { job_id: params.job_id, batch_ref: params.batch_ref });
      return { authorized: true };
    }
    if (request.method === 'receipts') {
      if (typeof params.session_id !== 'string') throw new Error('UNAUTHORIZED_ROOT');
      const authorization = this.roots.get(params.session_id);
      if (authorization === undefined) throw new Error('UNAUTHORIZED_ROOT');
      const plan = await this.domain.loadBatch(authorization.batch_ref);
      return this.domain.receiptSummaries(plan.job_id, plan.tasks.map(task => task.task_id));
    }
    if (request.method === 'cancel') {
      if (typeof params.job_id !== 'string' || ![...this.roots.values()].some(root => root.job_id === params.job_id) || this.handler === undefined) throw new Error('JOB_NOT_AUTHORIZED');
      await this.handler(params.job_id); return { cancelled: true };
    }
    throw new Error('UNKNOWN_CONTROL_METHOD');
  }
  async authorizeRoot(sessionId: string): Promise<{ job_id: string; batch_ref: string } | undefined> { return this.roots.get(sessionId); }
  installControl(handler: (jobId: string) => Promise<void>): () => void {
    if (this.handler !== undefined) throw new Error('CONTROL_HANDLER_ALREADY_INSTALLED');
    this.handler = handler;
    return () => { if (this.handler === handler) this.handler = undefined; };
  }
  async close(): Promise<void> {
    this.ready = false;
    for (const socket of this.sockets) socket.destroy();
    if (this.server !== undefined) await new Promise<void>(resolveClose => this.server!.close(() => resolveClose()));
    await unlink(this.path).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; });
  }
}
