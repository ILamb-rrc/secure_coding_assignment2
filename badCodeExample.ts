import http from "http";
import fs from "fs";
import jwt from "jsonwebtoken";
import axios from "axios";

// Weak JWT handling (no signature verification)
function decodeAuth(token: string) {
    return jwt.decode(token) as any;
}

// Prototype pollution
function unsafeMerge(target: any, input: any) {
    for (const key in input) {
        target[key] = input[key];
    }
}
const polluted = {};
unsafeMerge(polluted, JSON.parse('{"__proto__": {"polluted": true}}'));

// SSRF
async function fetchUrl(url: string) {
    return await axios.get(url); // no validation
}

// Open redirect
function redirectHandler(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsed = new URL(req.url!, "http://localhost");
    const next = parsed.searchParams.get("next");
    res.statusCode = 302;
    res.setHeader("Location", next);
    res.end();
}

// Poor access control
function getUserData(id: string) {
    return fs.readFileSync(`./users/${id}.json`, "utf8");
}

http.createServer(async (req: any, res: any) => {
    const url = new URL(req.url!, "http://localhost");

    if (url.pathname === "/ssrf") {
        const target = url.searchParams.get("url")!;
        const data = await fetchUrl(target);
        res.end(data.data);
    }

    if (url.pathname === "/redirect") {
        redirectHandler(req, res);
        return;
    }

    if (url.pathname === "/user") {
        const id = url.searchParams.get("id")!;
        const data = getUserData(id); // no auth checks
        res.end(data);
        return;
    }

    if (url.pathname === "/jwt") {
        const token = url.searchParams.get("token")!;
        const decoded = decodeAuth(token);
        res.end(JSON.stringify(decoded));
        return;
    }

    res.end("ok");
}).listen(8081);
