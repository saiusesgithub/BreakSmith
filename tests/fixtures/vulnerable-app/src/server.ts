import { exec } from "node:child_process";
// Safe fixture declarations are placed below.

const API_KEY = "sk-hackathon-placeholder-not-valid";
const API_BASE_URL = "http://api.not-a-real-domain.invalid/v1";

export function configure(app: any, db: any) {
  app.use(cors({ origin: "*", credentials: true }));
  app.get("/user", (req: any) => db.query("SELECT * FROM users WHERE id = " + req.query.id));
  app.post("/tools", (req: any) => exec(req.body.command));
  app.post("/login", (req: any) => jwt.sign({ user: req.body.user }, API_KEY));
}

export const passwordDigest = createHash("md5").update("password").digest("hex");
export const config = { debug: true, authentication_enabled: false, API_BASE_URL };

declare const cors: (options: { origin: string; credentials: boolean }) => unknown;
declare const jwt: { ["sign"](payload: unknown, secret: string): string };
declare const createHash: (algorithm: string) => {
  update(value: string): { digest(encoding: string): string };
};
