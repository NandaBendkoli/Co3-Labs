// /edge/hash-object/src/index.ts
import { serve } from "std/server";
import crypto from "crypto";
import fetch from "node-fetch"; // runtime may provide fetch

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE")!;

serve(async (req) => {
  try {
    if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

    const body = await req.json();
    const { path, secret } = body;

    // basic auth: server-only - verify
    if (secret !== Deno.env.get("EDGE_SECRET")) return new Response("Forbidden", { status: 403 });

    // Generate a signed URL for download (short-lived) using service role key via Supabase REST
    const url = `${SUPABASE_URL}/storage/v1/object/sign/${encodeURIComponent(path)}?expiresIn=120`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE}`,
      },
    });
    if (!res.ok) return new Response("Object not found", { status: 404 });
    const { signedURL } = await res.json();

    // stream the object and compute sha256
    const streamRes = await fetch(signedURL);
    if (!streamRes.ok) return new Response("Object not readable", { status: 500 });

    const hash = crypto.createHash("sha256");
    const reader = streamRes.body!.getReader();
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        size += value.length;
        hash.update(value);
      }
    }
    const sha256 = hash.digest("hex");
    return new Response(JSON.stringify({ sha256, size }), { status: 200, headers: { "Content-Type": "application/json" }});
  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ error: (err as Error).message }), { status: 500 });
  }
});
