type LoginResult = { token: string; expiresAt: number };

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class AuthError extends Error {
  constructor(
    message: string,
    public code: "INVALID_INPUT" | "INVALID_CREDENTIALS" | "NETWORK",
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export async function login(email: string, password: string): Promise<LoginResult> {
  if (!EMAIL_RE.test(email)) {
    throw new AuthError("Invalid email format", "INVALID_INPUT");
  }
  if (password.length < 8) {
    throw new AuthError("Password must be at least 8 characters", "INVALID_INPUT");
  }

  let res: Response;
  try {
    res = await fetch("https://api.example.com/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    throw new AuthError("Network request failed", "NETWORK");
  }

  if (res.status === 401) {
    throw new AuthError("Incorrect email or password", "INVALID_CREDENTIALS");
  }
  if (!res.ok) {
    throw new AuthError(`Login failed (${res.status})`, "NETWORK");
  }

  const data = (await res.json()) as { token: string; expiresAt: number };
  return { token: data.token, expiresAt: data.expiresAt };
}
