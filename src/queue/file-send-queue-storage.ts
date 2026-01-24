/**
 * AlgoChat - File Send Queue Storage
 *
 * Persists pending messages to a JSON file for offline support.
 */

import { mkdir, readFile, writeFile, unlink, chmod, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import type { PendingMessage } from '../models/pending-message';
import type { SendQueueStorage } from './send-queue';

/** Default directory name for AlgoChat data */
const DEFAULT_DIRECTORY = '.algochat';

/** Default filename for the queue */
const DEFAULT_FILENAME = 'queue.json';

/**
 * File-based persistent storage for the send queue.
 *
 * Stores pending messages as JSON in `~/.algochat/queue.json`.
 * Messages survive app crashes and restarts.
 *
 * @example
 * ```typescript
 * const storage = new FileSendQueueStorage();
 * const queue = new SendQueue({}, storage);
 *
 * // Load any pending messages from previous session
 * await queue.load();
 * ```
 */
export class FileSendQueueStorage implements SendQueueStorage {
    private customPath: string | null;

    /**
     * Creates a new file-based queue storage.
     *
     * @param customPath - Optional custom file path (for testing)
     */
    constructor(customPath?: string) {
        this.customPath = customPath ?? null;
    }

    /** Saves messages to the queue file */
    async save(messages: PendingMessage[]): Promise<void> {
        const filePath = await this.getQueueFilePath();

        if (messages.length === 0) {
            // Delete file if queue is empty
            try {
                await unlink(filePath);
            } catch (e) {
                // File doesn't exist, that's fine
                if ((e as NodeJS.ErrnoException).code !== 'ENOENT') {
                    throw e;
                }
            }
            return;
        }

        // Serialize with pretty printing and sorted keys
        const serialized = messages.map((m) => ({
            ...m,
            createdAt: m.createdAt.toISOString(),
            lastAttempt: m.lastAttempt?.toISOString(),
        }));
        const json = JSON.stringify(serialized, null, 2);

        // Ensure directory exists
        await mkdir(dirname(filePath), { recursive: true });

        // Write atomically by writing to temp file first
        const tempPath = `${filePath}.tmp`;
        await writeFile(tempPath, json, 'utf8');

        // Set restrictive permissions on Unix
        if (process.platform !== 'win32') {
            await chmod(tempPath, 0o600);
        }

        // Rename to final path (atomic on most filesystems)
        const { rename } = await import('node:fs/promises');
        await rename(tempPath, filePath);
    }

    /** Loads messages from the queue file */
    async load(): Promise<PendingMessage[]> {
        const filePath = await this.getQueueFilePath();

        try {
            await stat(filePath);
        } catch {
            // File doesn't exist
            return [];
        }

        const json = await readFile(filePath, 'utf8');
        const parsed = JSON.parse(json) as Array<{
            id: string;
            recipient: string;
            content: string;
            replyContext?: { messageId: string; preview: string };
            createdAt: string;
            retryCount: number;
            lastAttempt?: string;
            status: string;
            lastError?: string;
        }>;

        return parsed.map((m) => ({
            id: m.id,
            recipient: m.recipient,
            content: m.content,
            replyContext: m.replyContext,
            createdAt: new Date(m.createdAt),
            retryCount: m.retryCount,
            lastAttempt: m.lastAttempt ? new Date(m.lastAttempt) : undefined,
            status: m.status as PendingMessage['status'],
            lastError: m.lastError,
        }));
    }

    /** Gets the queue file path */
    private async getQueueFilePath(): Promise<string> {
        if (this.customPath) {
            return this.customPath;
        }

        const directory = join(homedir(), DEFAULT_DIRECTORY);
        return join(directory, DEFAULT_FILENAME);
    }
}
