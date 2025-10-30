import { createServer } from '@graphql-yoga/node';
import { createClient } from '@supabase/supabase-js';
import { typeDefs } from './schema';
import resolvers from './resolvers';
import dotenv from 'dotenv';
dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

const server = createServer({
  schema: {
    typeDefs,
    resolvers,
  },
  context: ({ request }) => {
    // extract user and token from Authorization header (Bearer ...),
    // verify JWT via supabase admin or decode (we'll rely on supabase client)
    const authHeader = request.headers.get('authorization') || '';
    return { supabaseAdmin, authHeader };
  }
});

server.start(() => console.log('GraphQL server started on http://localhost:4000'));
