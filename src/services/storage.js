
const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

const STORAGE_DIR = path.resolve(__dirname, "../../uploads");

async function ensureStorageDirectory() {
    await fs.mkdir(STORAGE_DIR, { recursive: true });
}

async function saveTemporaryFile(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
        throw new Error("A non-empty file buffer is required");
    }

    await ensureStorageDirectory();

    const storageKey = randomUUID();
    const filePath = path.join(STORAGE_DIR, storageKey);

    await fs.writeFile(filePath, buffer, { flag: "wx", mode: 0o600 });

    return {
        storageKey,
        filePath,
        size: buffer.length
    };
}

async function getFilePath(storageKey) {
    if (
        typeof storageKey !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(storageKey)
    ) {
        throw new Error("Invalid storage key");
    }

    const filePath = path.join(STORAGE_DIR, storageKey);

    await fs.access(filePath);

    return filePath;
}

async function deleteFile(storageKey) {
    const filePath = await getFilePath(storageKey);
    await fs.unlink(filePath);
}

module.exports = {
    ensureStorageDirectory,
    saveTemporaryFile,
    getFilePath,
    deleteFile
};
