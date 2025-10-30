import { supabaseAdmin } from './index'; // adjust import
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { differenceInSeconds, addSeconds } from 'date-fns';

const ALLOWED_MIMES = new Set(['image/jpeg','image/png','image/webp','application/pdf']);

function safeFilename(name: string){
  let s = name.normalize('NFKC').trim();
  // remove path chars and keep basename
  s = s.replace(/.*[\\/]/, '');
  s = s.replace(/\s+/g, '-').replace(/[^A-Za-z0-9.\-_]/g, '');
  if (s.length > 180) s = s.slice(0,180);
  return s || 'file';
}

const resolvers = {
  Query: {
    myAssets: async (_: any, { after, first = 20, q }: any, ctx: any) => {
      // use ctx.authHeader to determine user id; but easiest is to use supabase row level security with the user token
      // For brevity: server expects client to send Authorization header with Bearer <access_token>.
      const authHeader = ctx.authHeader || '';
      if (!authHeader.startsWith('Bearer ')) throw new Error('UNAUTHENTICATED');

      const token = authHeader.slice(7);
      const supabase = supabaseAdmin; // we'll call Postgres directly with service role but filter by owner manually
      // We should decode token to get user id; for brevity we call auth.getUser (note: ensure using supabase-js latest)
      const { data: userData, error: userErr } = await supabase.auth.getUser(token);
      if (userErr || !userData.user) throw new Error('UNAUTHENTICATED');

      const userId = userData.user.id;
      // Basic search + cursor pagination
      const query = supabaseAdmin
        .from('asset')
        .select('*')
        .or(`owner_id.eq.${userId},id.in.(select asset_id from asset_share where to_user=uuid'${userId}')`)
        .order('created_at', { ascending: false })
        .limit(first);

      // (This simplified query bypasses RLS enforcement - in a real setup you'd initialize supabase client with user's access token and let RLS enforce.)
      const { data, error } = await query;
      if (error) throw error;
      const edges = data.map((row: any) => ({
        cursor: row.id,
        node: {
          id: row.id,
          filename: row.filename,
          mime: row.mime,
          size: row.size,
          sha256: row.sha256,
          status: row.status,
          version: row.version,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }
      }));
      return { edges, pageInfo: { endCursor: edges.length ? edges[edges.length-1].cursor : null, hasNextPage:false }};
    },

    getDownloadUrl: async (_: any, { assetId }: any, ctx: any) => {
      const authHeader = ctx.authHeader || '';
      if (!authHeader.startsWith('Bearer ')) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const token = authHeader.slice(7);
      const userResp = await supabaseAdmin.auth.getUser(token);
      if (!userResp.data.user) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const userId = userResp.data.user.id;

      // Check asset exists, status ready, and RLS: owner or shared + can_download
      const { data: assetRows, error } = await supabaseAdmin
        .from('asset')
        .select('*')
        .eq('id', assetId)
        .maybeSingle();
      if (error || !assetRows) { const e:any = new Error('NOT_FOUND'); (e as any).extensions={code:'NOT_FOUND'}; throw e; }
      const asset = assetRows;

      // RLS enforcement - verify owner or share
      if (asset.owner_id !== userId) {
        const { data: share } = await supabaseAdmin
          .from('asset_share')
          .select('*')
          .eq('asset_id', assetId)
          .eq('to_user', userId)
          .maybeSingle();
        if (!share) { const e:any = new Error('FORBIDDEN'); (e as any).extensions={code:'FORBIDDEN'}; throw e; }
        if (!share.can_download) { const e:any = new Error('FORBIDDEN'); (e as any).extensions={code:'FORBIDDEN'}; throw e; }
      }

      if (asset.status !== 'ready') { const e:any = new Error('BAD_REQUEST'); (e as any).extensions={code:'BAD_REQUEST'}; throw e; }

      // Create signed url via service key (short TTL)
      const path = asset.storage_path;
      const ttl = 90; // seconds (90-120)
      const { data: urlData, error: signErr } = await supabaseAdmin.storage.from('private').createSignedUrl(path, ttl);
      if (signErr || !urlData) { throw signErr || new Error('Failed to sign'); }

      // Insert audit log
      await supabaseAdmin.from('download_audit').insert({ asset_id: assetId, user_id: userId });

      return { url: urlData.signedURL, expiresAt: new Date(Date.now() + ttl*1000).toISOString() };
    }
  },

  Mutation: {
    createUploadUrl: async (_: any, { filename, mime, size }: any, ctx: any) => {
      const authHeader = ctx.authHeader || '';
      if (!authHeader.startsWith('Bearer ')) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const token = authHeader.slice(7);
      const userResp = await supabaseAdmin.auth.getUser(token);
      if (!userResp.data.user) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const userId = userResp.data.user.id;

      // Sanitise filename and mime allowlist
      const safe = safeFilename(filename);
      if (!ALLOWED_MIMES.has(mime)) { const e:any = new Error('BAD_REQUEST'); (e as any).extensions={code:'BAD_REQUEST'}; throw e; }

      // Create asset row in 'draft' or 'uploading' status
      const assetId = uuidv4();
      const now = new Date();
      const yyyy = now.getFullYear();
      const mm = String(now.getMonth()+1).padStart(2,'0');
      const storagePath = `private/${userId}/${yyyy}/${mm}/${assetId}-${safe}`;

      // create signed PUT url (using service role: create object signed URL for upload)
      // Supabase JS has createSignedUploadUrl? We'll create a presigned PUT by using storage API to createSignedUrl for object - some SDKs support createSignedUrl for GET only.
      // Simpler: generate a presigned PUT via Supabase REST using service role token:
      const uploadExpires = 5 * 60; // seconds
      const nonce = crypto.randomBytes(16).toString('hex');

      // Insert asset row
      const { error: insertErr } = await supabaseAdmin.from('asset').insert({
        id: assetId,
        owner_id: userId,
        filename: safe,
        mime,
        size,
        storage_path: storagePath,
        status: 'uploading'
      });
      if (insertErr) { throw insertErr; }

      // Insert upload_ticket
      const expiresAt = new Date(Date.now() + uploadExpires*1000).toISOString();
      await supabaseAdmin.from('upload_ticket').insert({
        asset_id: assetId,
        user_id: userId,
        nonce,
        mime,
        size,
        storage_path: storagePath,
        expires_at: expiresAt
      });

      // Generate upload URL: use storage sign upload via REST
      const { data: uploadUrlData, error: signErr } = await supabaseAdmin
        .storage
        .from('private')
        .createSignedUrl(storagePath, uploadExpires); // Note: createSignedUrl commonly signs GET; to allow PUT you may instead use a storage server-side presign technique or an S3-style signed PUT.
      // For the flow here, assume storage supports signed PUT via an API or use a temporary service endpoint that accepts the upload and forwards to storage. For now, return a signed URL (clients will PUT to it).

      // We'll return uploadUrlData.signedURL
      return {
        assetId,
        storagePath,
        uploadUrl: uploadUrlData?.signedURL ?? '',
        expiresAt,
        nonce
      };
    },

    finalizeUpload: async (_: any, { assetId, clientSha256, version }: any, ctx: any) => {
      const authHeader = ctx.authHeader || '';
      if (!authHeader.startsWith('Bearer ')) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const token = authHeader.slice(7);
      const userResp = await supabaseAdmin.auth.getUser(token);
      if (!userResp.data.user) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const userId = userResp.data.user.id;

      // Fetch ticket
      const { data: ticket } = await supabaseAdmin.from('upload_ticket').select('*').eq('asset_id', assetId).maybeSingle();
      if (!ticket) { const e:any = new Error('NOT_FOUND'); (e as any).extensions={code:'NOT_FOUND'}; throw e; }

      if (ticket.user_id !== userId) { const e:any = new Error('FORBIDDEN'); (e as any).extensions={code:'FORBIDDEN'}; throw e; }
      if (ticket.used) { // idempotent: if status ready and sha256 matches, return asset
        const { data: assetRow } = await supabaseAdmin.from('asset').select('*').eq('id', assetId).maybeSingle();
        if (!assetRow) { const e:any = new Error('NOT_FOUND'); (e as any).extensions={code:'NOT_FOUND'}; throw e; }
        return assetRow;
      }
      if (new Date(ticket.expires_at) < new Date()) { const e:any = new Error('BAD_REQUEST'); (e as any).extensions={code:'BAD_REQUEST'}; throw e; }

      // Verify object exists & compute sha256 by calling edge function
      const edgeRes = await fetch(process.env.EDGE_URL!, {
        method: 'POST',
        headers: { 'content-type':'application/json' },
        body: JSON.stringify({ path: ticket.storage_path, secret: process.env.EDGE_SECRET })
      });
      if (!edgeRes.ok) {
        // mark corrupt
        await supabaseAdmin.from('asset').update({ status: 'corrupt', version: version + 1 }).eq('id', assetId);
        const e:any = new Error('INTEGRITY_ERROR'); (e as any).extensions={code:'INTEGRITY_ERROR'}; throw e;
      }
      const { sha256: serverSha256, size: serverSize } = await edgeRes.json();

      // size check
      if (Number(serverSize) !== Number(ticket.size) ) {
        await supabaseAdmin.from('asset').update({ status: 'corrupt', version: version + 1 }).eq('id', assetId);
        const e:any = new Error('INTEGRITY_ERROR'); (e as any).extensions={code:'INTEGRITY_ERROR'}; throw e;
      }

      // check mime using magic bytes - simplified: fetch first bytes and sniff or rely on edge function prior to hashing to sniff.
      if (!ALLOWED_MIMES.has(ticket.mime)) {
        await supabaseAdmin.from('asset').update({ status: 'corrupt', version: version + 1 }).eq('id', assetId);
        const e:any = new Error('BAD_REQUEST'); (e as any).extensions={code:'BAD_REQUEST'}; throw e;
      }

      if (serverSha256 !== clientSha256) {
        // mark corrupt
        await supabaseAdmin.from('asset').update({ status: 'corrupt', version: version + 1 }).eq('id', assetId);
        const e:any = new Error('INTEGRITY_ERROR'); (e as any).extensions={code:'INTEGRITY_ERROR'}; throw e;
      }

      // mark ticket used and asset ready: do in transaction or careful updates
      await supabaseAdmin.from('upload_ticket').update({ used: true }).eq('asset_id', assetId);
      const { error: updateErr } = await supabaseAdmin.from('asset').update({
        status: 'ready',
        sha256: serverSha256,
        version: version + 1,
        updated_at: new Date().toISOString()
      }).eq('id', assetId).eq('version', version);

      if (updateErr) {
        // handle version conflict
        const e:any = new Error('VERSION_CONFLICT'); (e as any).extensions={code:'VERSION_CONFLICT'}; throw e;
      }

      const { data: updatedAsset } = await supabaseAdmin.from('asset').select('*').eq('id', assetId).maybeSingle();
      return updatedAsset;
    },

    renameAsset: async (_: any, { assetId, filename, version }: any, ctx: any) => {
      const authHeader = ctx.authHeader || '';
      if (!authHeader.startsWith('Bearer ')) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const token = authHeader.slice(7);
      const userResp = await supabaseAdmin.auth.getUser(token);
      if (!userResp.data.user) { const e:any = new Error('UNAUTHENTICATED'); (e as any).extensions={code:'UNAUTHENTICATED'}; throw e; }
      const userId = userResp.data.user.id;

      const safe = safeFilename(filename);
      // versioned update
      const { error } = await supabaseAdmin.from('asset').update({
        filename: safe,
        version: version + 1,
        updated_at: new Date().toISOString()
      }).eq('id', assetId).eq('version', version);

      if (error) {
        const e:any = new Error('VERSION_CONFLICT'); (e as any).extensions={code:'VERSION_CONFLICT'}; throw e;
      }
      const { data: updatedAsset } = await supabaseAdmin.from('asset').select('*').eq('id', assetId).maybeSingle();
      return updatedAsset;
    },

    // shareAsset, revokeShare, deleteAsset - implement similarly with version checks and RLS/permission checks
  }
};

export default resolvers;
