const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { DatabaseSync } = require("node:sqlite");

// configuration

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

const APP_ORIGIN = process.env.APP_ORIGIN
    ? new URL(process.env.APP_ORIGIN).origin
    : null;

const SECURE_COOKIE =
    process.env.NODE_ENV === "production" ||
    APP_ORIGIN?.startsWith("https:");

if (
    process.env.NODE_ENV === "production" &&
    !APP_ORIGIN?.startsWith("https:")
) {
    throw new Error(
        "Set APP_ORIGIN to your public HTTPS origin in production."
    );
}

const SESSION_DURATION = 3 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = "phenomania_session";

// developer bypass

const DEV_ACCESS_CODE = process.env.PHENOMANIA_DEV_CODE || "";
const DEV_BYPASS_ENABLED = DEV_ACCESS_CODE.length >= 24;

const PUBLIC = path.join(__dirname, "public");
const DATA = path.join(__dirname, "data");

// database

fs.mkdirSync(DATA, {
    recursive: true,
    mode: 0o700
});

const db = new DatabaseSync(
    path.join(DATA, "accounts.sqlite")
);

db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id)
            ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sessions_expires
        ON sessions(expires_at);
`);

// password security

const scrypt = promisify(crypto.scrypt);

const scryptOptions = {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024
};

const hashPassword = (password, salt) =>
    scrypt(password, salt, 64, scryptOptions);

const tokenHash = token =>
    crypto.createHash("sha256").update(token).digest("hex");

const dummySalt = crypto.randomBytes(16).toString("hex");

const cookieFlags =
    `; Path=/; HttpOnly; SameSite=Strict` +
    `${SECURE_COOKIE ? "; Secure" : ""}`;

// login attempt limits

const attempts = new Map();

const RATE_WINDOW = 15 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 12;

function rateAllowed(req) {
    const key = req.socket.remoteAddress || "unknown";
    const now = Date.now();

    let entry = attempts.get(key);

    if (!entry || entry.until <= now) {
        entry = {
            count: 0,
            until: now + RATE_WINDOW
        };

        attempts.set(key, entry);
    }

    if (entry.count >= MAX_AUTH_ATTEMPTS) {
        return false;
    }

    entry.count++;

    return true;
}

// expired session cleanup

setInterval(() => {
    const now = Date.now();

    for (const [key, entry] of attempts) {
        if (entry.until <= now) {
            attempts.delete(key);
        }
    }

    for (const [key, session] of devSessions) {
        if (session.expiresAt <= now) {
            devSessions.delete(key);
        }
    }

    try {
        db.prepare(
            "DELETE FROM sessions WHERE expires_at <= ?"
        ).run(now);
    } catch (error) {
        console.error("Session cleanup:", error.message);
    }
}, 60 * 1000).unref();

// response functions

function json(res, status, body) {
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
    });

    res.end(JSON.stringify(body));
}

function redirect(res, target) {
    res.writeHead(302, {
        Location: target,
        "Cache-Control": "no-store"
    });

    res.end();
}

// sessions

const devSessions = new Map();

function getToken(req) {
    const cookie = (req.headers.cookie || "")
        .split(";")
        .map(v => v.trim())
        .find(v => v.startsWith(COOKIE_NAME + "="));

    const token = cookie?.slice(COOKIE_NAME.length + 1);

    return /^[a-f0-9]{64}$/.test(token || "")
        ? token
        : null;
}

function getSession(req) {
    const token = getToken(req);

    if (!token) return null;

    const hash = tokenHash(token);
    const devSession = devSessions.get(hash);

    if (devSession) {
        if (devSession.expiresAt <= Date.now()) {
            devSessions.delete(hash);
            return null;
        }

        return DEV_BYPASS_ENABLED ? devSession : null;
    }

    return db.prepare(`
        SELECT
            users.id,
            users.username,
            sessions.expires_at AS expiresAt

        FROM sessions

        JOIN users
            ON users.id = sessions.user_id

        WHERE sessions.token_hash = ?
            AND sessions.expires_at > ?
    `).get(
        tokenHash(token),
        Date.now()
    ) || null;
}

function revokeSession(req) {
    const token = getToken(req);

    if (token) {
        const hash = tokenHash(token);
        devSessions.delete(hash);

        db.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
        ).run(hash);
    }
}

function createDevSession(req, res) {
    revokeSession(req);

    const token = crypto.randomBytes(32).toString("hex");

    const session = {
        id: -1,
        username: "Dev_001",
        expiresAt: Date.now() + SESSION_DURATION
    };

    devSessions.set(tokenHash(token), session);

    res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${token}; Max-Age=${SESSION_DURATION / 1000}${cookieFlags}`
    );

    return {
        username: session.username,
        expiresAt: session.expiresAt
    };
}

function createSession(req, res, user) {
    revokeSession(req);

    const token = crypto.randomBytes(32).toString("hex");

    const expiresAt = Date.now() + SESSION_DURATION;

    db.prepare(`
        INSERT INTO sessions (
            token_hash,
            user_id,
            expires_at
        ) VALUES (?, ?, ?)
    `).run(
        tokenHash(token),
        user.id,
        expiresAt
    );

    res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${token}; Max-Age=${SESSION_DURATION / 1000}${cookieFlags}`
    );

    return {
        username: user.username,
        expiresAt
    };
}

// request handling

function readJson(req) {
    return new Promise((resolve, reject) => {
        let size = 0;

        const chunks = [];

        req.on("data", chunk => {
            size += chunk.length;

            if (size <= 8192) {
                chunks.push(chunk);
            }
        });

        req.on("end", () => {
            if (size > 8192) {
                return reject(
                    Object.assign(
                        new Error("Request too large."),
                        { status: 413 }
                    )
                );
            }

            try {
                const value = JSON.parse(
                    Buffer.concat(chunks).toString("utf8")
                );

                if (
                    !value ||
                    typeof value !== "object" ||
                    Array.isArray(value)
                ) {
                    throw new Error();
                }

                resolve(value);
            } catch {
                reject(
                    Object.assign(
                        new Error("Invalid request."),
                        { status: 400 }
                    )
                );
            }
        });

        req.on("error", reject);
    });
}

function safeOrigin(req) {
    const expected =
        APP_ORIGIN || `http://${req.headers.host}`;

    return (
        req.headers.origin === expected &&
        req.headers["sec-fetch-site"] !== "cross-site"
    );
}

const string = v =>
    typeof v === "string" ? v : "";

// create account

async function register(req, res, body) {
    const username = string(body.username).trim();

    const email = string(body.email)
        .trim()
        .toLowerCase();

    const password = string(body.password);

    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
        return json(res, 400, {
            error: "Username must be 3–20 letters, numbers or underscores."
        });
    }

    if (
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
        return json(res, 400, {
            error: "Enter a valid email address."
        });
    }

    if (password.length < 12 || password.length > 128) {
        return json(res, 400, {
            error: "Password must be 12–128 characters."
        });
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const hash = (
        await hashPassword(password, salt)
    ).toString("hex");

    let user;

    try {
        const result = db.prepare(`
            INSERT INTO users (
                username,
                email,
                password_hash,
                salt,
                created_at
            ) VALUES (?, ?, ?, ?, ?)
        `).run(
            username,
            email,
            hash,
            salt,
            Date.now()
        );

        user = {
            id: result.lastInsertRowid,
            username
        };

    } catch (error) {
        if (
            error.errcode === 2067 ||
            /UNIQUE constraint failed/.test(error.message)
        ) {
            return json(res, 409, {
                error: "That username or email is already registered."
            });
        }

        throw error;
    }

    return json(
        res,
        201,
        createSession(req, res, user)
    );
}

// login

async function login(req, res, body) {
    const identifier = string(body.identifier).trim();
    const password = string(body.password);

    if (
        !identifier ||
        identifier.length > 254 ||
        !password ||
        password.length > 128
    ) {
        return json(res, 401, {
            error: "Incorrect username, email or password."
        });
    }

    const user = db.prepare(`
        SELECT * FROM users
        WHERE username = ? OR email = ?
    `).get(identifier, identifier);

    const candidate = await hashPassword(
        password,
        user?.salt || dummySalt
    );

    const expected = user
        ? Buffer.from(user.password_hash, "hex")
        : Buffer.alloc(64);

    if (
        !crypto.timingSafeEqual(candidate, expected) ||
        !user
    ) {
        return json(res, 401, {
            error: "Incorrect username, email or password."
        });
    }

    return json(
        res,
        200,
        createSession(req, res, user)
    );
}

// global chat

const CHAT_MAX_LENGTH = 250;
const CHAT_COOLDOWN = 750;
const CHAT_MAX_CONNECTIONS = 1000;
const CHAT_MAX_CONNECTIONS_PER_USER = 8;

const chatClients = new Set();
const chatLastSent = new Map();

function closeChatClient(client, expired = false) {
    chatClients.delete(client);

    if (client.res.destroyed || client.res.writableEnded) return;

    if (expired) {
        client.res.write("event: session-expired\ndata: {}\n\n");
    }

    client.res.end();
}

function chatClientValid(client) {
    const user = getSession(client.req);

    return user && user.id === client.userId;
}

function writeChatEvent(client, event) {
    if (client.res.destroyed || client.res.writableEnded) {
        chatClients.delete(client);
        return;
    }

    if (!client.res.write(event)) {
        chatClients.delete(client);
        client.res.destroy();
    }
}

function openChatStream(req, res) {
    const user = getSession(req);

    if (!user) {
        return json(res, 401, {
            error: "Not logged in."
        });
    }

    let connections = 0;

    for (const client of chatClients) {
        if (client.userId === user.id) connections++;
    }

    if (
        chatClients.size >= CHAT_MAX_CONNECTIONS ||
        connections >= CHAT_MAX_CONNECTIONS_PER_USER
    ) {
        return json(res, 429, {
            error: "Too many chat connections."
        });
    }

    res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no"
    });

    res.flushHeaders();

    const client = {
        req,
        res,
        userId: user.id
    };

    chatClients.add(client);

    res.on("close", () => chatClients.delete(client));
    res.on("error", () => chatClients.delete(client));

    writeChatEvent(client, "retry: 2000\n: connected\n\n");
}

async function sendChatMessage(req, res) {
    if (!safeOrigin(req)) {
        return json(res, 403, {
            error: "Invalid request origin."
        });
    }

    if (!getSession(req)) {
        return json(res, 401, {
            error: "Not logged in."
        });
    }

    if (
        !(req.headers["content-type"] || "")
            .toLowerCase()
            .startsWith("application/json")
    ) {
        return json(res, 415, {
            error: "JSON required."
        });
    }

    const body = await readJson(req);
    const message = string(body.message).trim();

    const user = getSession(req);

    if (!user) {
        return json(res, 401, {
            error: "Not logged in."
        });
    }

    if (
        !message ||
        message.length > CHAT_MAX_LENGTH ||
        /[\r\n\x00-\x1f\x7f]/.test(message)
    ) {
        return json(res, 400, {
            error: "Enter a message of 1–250 characters on one line."
        });
    }

    const now = Date.now();

    if (now - (chatLastSent.get(user.id) || 0) < CHAT_COOLDOWN) {
        return json(res, 429, {
            error: "You are sending messages too quickly."
        });
    }

    chatLastSent.set(user.id, now);

    const event = `data: ${JSON.stringify({
        username: user.username,
        message
    })}\n\n`;

    for (const client of chatClients) {
        if (!chatClientValid(client)) {
            closeChatClient(client, true);
        } else {
            writeChatEvent(client, event);
        }
    }

    return json(res, 200, {
        success: true
    });
}

// keep chat connections alive

setInterval(() => {
    const now = Date.now();

    for (const [id, sentAt] of chatLastSent) {
        if (now - sentAt >= CHAT_COOLDOWN) {
            chatLastSent.delete(id);
        }
    }

    for (const client of chatClients) {
        if (!chatClientValid(client)) {
            closeChatClient(client, true);
        } else {
            writeChatEvent(client, ": heartbeat\n\n");
        }
    }
}, 15000).unref();

// file types

const types = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".wav": "audio/wav",
    ".m4a": "audio/mp4",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".wasm": "application/wasm",
    ".txt": "text/plain; charset=utf-8"
};

// serve game files

async function serveFile(req, res, pathname) {
    const parts = pathname.split("/").filter(Boolean);

    if (
        parts.some(part =>
            part.startsWith(".") ||
            part.includes("\\") ||
            part.includes("\0")
        )
    ) {
        return json(res, 404, {
            error: "Not found."
        });
    }

    let file = path.resolve(PUBLIC, ...parts);

    if (!file.startsWith(PUBLIC + path.sep)) {
        return json(res, 404, {
            error: "Not found."
        });
    }

    let stat;

    try {
        file = await fs.promises.realpath(file);

        if (!file.startsWith(PUBLIC + path.sep)) {
            return json(res, 404, {
                error: "Not found."
            });
        }

        stat = await fs.promises.stat(file);

        if (!stat.isFile()) {
            throw new Error();
        }

    } catch {
        return json(res, 404, {
            error: "File not found."
        });
    }

    const type =
        types[path.extname(file).toLowerCase()] ||
        "application/octet-stream";

    res.writeHead(200, {
        "Content-Type": type,
        "Content-Length": stat.size,
        "Cache-Control": type.startsWith("text/html")
            ? "no-store"
            : "no-cache"
    });

    if (req.method === "HEAD") {
        return res.end();
    }

    const stream = fs.createReadStream(file);

    stream.on("error", () => res.destroy());

    stream.pipe(res);
}

// server

const server = http.createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("X-Frame-Options", "DENY");

    try {
        let pathname;

        try {
            pathname = decodeURIComponent(
                new URL(req.url, "http://localhost").pathname
            );
        } catch {
            return json(res, 400, {
                error: "Invalid URL."
            });
        }

        pathname = path.posix
            .normalize(pathname.replace(/\\/g, "/"))
            .replace(/\/$/, "") || "/";

        // api

        if (pathname.startsWith("/api/")) {

            // public deployment developer session

            if (pathname === "/api/dev-session") {
                if (!DEV_BYPASS_ENABLED) {
                    return json(res, 404, {
                        error: "Developer access is not configured."
                    });
                }

                if (req.method !== "POST") {
                    return json(res, 405, {
                        error: "Method not allowed."
                    });
                }

                if (!safeOrigin(req)) {
                    return json(res, 403, {
                        error: "Invalid request origin."
                    });
                }

                if (
                    !(req.headers["content-type"] || "")
                        .toLowerCase()
                        .startsWith("application/json")
                ) {
                    return json(res, 415, {
                        error: "JSON required."
                    });
                }

                if (!rateAllowed(req)) {
                    return json(res, 429, {
                        error: "Too many attempts. Please try again later."
                    });
                }

                const body = await readJson(req);
                const code = string(body.code);

                const suppliedHash = crypto
                    .createHash("sha256")
                    .update(code)
                    .digest();

                const expectedHash = crypto
                    .createHash("sha256")
                    .update(DEV_ACCESS_CODE)
                    .digest();

                if (
                    !code ||
                    !crypto.timingSafeEqual(
                        suppliedHash,
                        expectedHash
                    )
                ) {
                    return json(res, 401, {
                        error: "Incorrect developer code."
                    });
                }

                return json(
                    res,
                    200,
                    createDevSession(req, res)
                );
            }

            // receive global chat messages

            if (pathname === "/api/chat/stream") {
                if (req.method !== "GET") {
                    return json(res, 405, {
                        error: "Method not allowed."
                    });
                }

                if (
                    req.headers["sec-fetch-site"] === "cross-site" ||
                    (req.headers.origin && !safeOrigin(req))
                ) {
                    return json(res, 403, {
                        error: "Invalid request origin."
                    });
                }

                return openChatStream(req, res);
            }

            // send global chat messages

            if (pathname === "/api/chat/messages") {
                if (req.method !== "POST") {
                    return json(res, 405, {
                        error: "Method not allowed."
                    });
                }

                return await sendChatMessage(req, res);
            }

            // account session

            if (
                pathname === "/api/session" &&
                req.method === "GET"
            ) {
                const user = getSession(req);

                return user
                    ? json(res, 200, {
                        username: user.username,
                        expiresAt: user.expiresAt
                    })
                    : json(res, 401, {
                        error: "Not logged in."
                    });
            }

            if (
                ![
                    "/api/register",
                    "/api/login",
                    "/api/logout"
                ].includes(pathname)
            ) {
                return json(res, 404, {
                    error: "Not found."
                });
            }

            if (req.method !== "POST") {
                return json(res, 405, {
                    error: "Method not allowed."
                });
            }

            if (!safeOrigin(req)) {
                return json(res, 403, {
                    error: "Invalid request origin."
                });
            }

            // logout

            if (pathname === "/api/logout") {
                revokeSession(req);

                for (const client of chatClients) {
                    if (!chatClientValid(client)) {
                        closeChatClient(client, true);
                    }
                }

                res.setHeader(
                    "Set-Cookie",
                    `${COOKIE_NAME}=; Max-Age=0${cookieFlags}`
                );

                return json(res, 200, {
                    success: true
                });
            }

            if (
                !(req.headers["content-type"] || "")
                    .toLowerCase()
                    .startsWith("application/json")
            ) {
                return json(res, 415, {
                    error: "JSON required."
                });
            }

            if (!rateAllowed(req)) {
                return json(res, 429, {
                    error: "Too many attempts. Please try again later."
                });
            }

            const body = await readJson(req);

            return await (
                pathname === "/api/register"
                    ? register(req, res, body)
                    : login(req, res, body)
            );
        }

        // website pages

        if (
            req.method !== "GET" &&
            req.method !== "HEAD"
        ) {
            return json(res, 405, {
                error: "Method not allowed."
            });
        }

        if (
            pathname === "/" ||
            pathname.toLowerCase() === "/index.html"
        ) {
            if (getSession(req)) {
                return redirect(res, "/phenomania.html");
            }

            return await serveFile(
                req,
                res,
                "/index.html"
            );
        }

        if (pathname.toLowerCase() === "/phenomania.html") {

            if (!getSession(req)) {
                return redirect(res, "/index.html");
            }

            return await serveFile(
                req,
                res,
                "/phenomania.html"
            );
        }

        return await serveFile(req, res, pathname);

    } catch (error) {
        if (error.status) {
            return json(res, error.status, {
                error: error.message
            });
        }

        console.error(error);

        if (!res.headersSent) {
            return json(res, 500, {
                error: "Account server error."
            });
        }

        res.destroy();
    }
});

// start server

server.requestTimeout = 15000;
server.headersTimeout = 10000;

server.listen(PORT, HOST, () => {
    console.log(
        `Phenomania is running at http://${HOST}:${PORT}`
    );
});
