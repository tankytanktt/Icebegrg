require('dotenv').config();
const express  = require('express');
const session  = require('express-session');
const fetch    = require('node-fetch');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;
const DISCORD_API = 'https://discord.com/api/v10';

// ── Supabase client ──────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Supabase session store ────────────────────────────────────────────────────
// Stores sessions in Supabase `sessions` table so they survive restarts/deploys
const SupabaseStore = require('express-session').Store;

class SupabaseSessionStore extends SupabaseStore {
  async get(sid, cb) {
    try {
      const { data } = await supabase.from('sessions').select('sess,expire').eq('sid', sid).single();
      if (!data) return cb(null, null);
      if (new Date(data.expire) < new Date()) {
        await supabase.from('sessions').delete().eq('sid', sid);
        return cb(null, null);
      }
      cb(null, data.sess);
    } catch(e) { cb(e); }
  }
  async set(sid, sess, cb) {
    try {
      const expire = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      await supabase.from('sessions').upsert({ sid, sess, expire }, { onConflict: 'sid' });
      cb(null);
    } catch(e) { cb(e); }
  }
  async destroy(sid, cb) {
    try {
      await supabase.from('sessions').delete().eq('sid', sid);
      cb(null);
    } catch(e) { cb(e); }
  }
  async touch(sid, sess, cb) {
    await this.set(sid, sess, cb);
  }
}

// ── Middleware ───────────────────────────────────────────────────────────────
app.set('trust proxy', 1); // trust Render's proxy so secure cookies work
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SupabaseSessionStore(),
  secret: process.env.SESSION_SECRET || 'esports-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, secure: true, sameSite: 'none' }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── File uploads ─────────────────────────────────────────────────────────────
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename:    (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-z0-9.]/gi, '-'))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── Auth helpers ─────────────────────────────────────────────────────────────
function isEnvAdmin(userId) {
  return (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).includes(String(userId));
}

// ── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireMember(req, res, next) {
  if (!req.session.user)     return res.status(401).json({ error: 'Not authenticated' });
  if (!req.session.isMember) return res.status(403).json({ error: 'Not a verified server member' });
  next();
}
function requireAdminPage(req, res, next) {
  if (!req.session.user)    return res.redirect('/?error=not_logged_in');
  if (!req.session.isAdmin) return res.redirect('/?error=not_admin');
  next();
}
function requireAdminApi(req, res, next) {
  if (!req.session.user)    return res.status(401).json({ error: 'Not authenticated' });
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Auction helpers ───────────────────────────────────────────────────────────
async function getAuction(tournamentId) {
  if (!tournamentId) throw new Error('Tournament ID required');
  const { data, error } = await supabase.from('auction_state').select('*').eq('tournament_id', tournamentId).single();
  if (error || !data) {
    return {
      tournament_id: tournamentId,
      teams: [], current_index: 0, current_bid: 0, current_bidder_id: null,
      owner1: { name: 'Owner 1', points: 100000, roster: [] },
      owner2: { name: 'Owner 2', points: 100000, roster: [] },
      started: false, concluded: false
    };
  }
  return data;
}
function toFE(a) {  // snake_case → camelCase for frontend
  return {
    tournamentId: a.tournament_id,
    teams: a.teams, currentIndex: a.current_index, currentBid: a.current_bid,
    currentBidderId: a.current_bidder_id,
    owner1: a.owner1, owner2: a.owner2,
    started: a.started, concluded: a.concluded,
    bidAt: a.bid_at || null   // ISO timestamp of last bid, for synced timer
  };
}
function teamToFE(t) {  // registration snake_case → camelCase
  return { ...t, tournamentId: t.tournament_id, teamName: t.team_name, captainDiscordId: t.captain_discord_id, captainUsername: t.captain_username, registeredAt: t.registered_at };
}

// ── Discord OAuth2 ────────────────────────────────────────────────────────────
app.get('/auth/discord', (req, res) => {
  if (!process.env.CLIENT_ID) return res.redirect('/?error=not_configured');
  const state = Math.random().toString(36).substring(2, 15);
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    response_type: 'code',
    scope: 'identify guilds',
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);
  if (!code)  return res.redirect('/?error=no_code');
  if (state !== req.session.oauthState) return res.redirect('/?error=invalid_state');

  try {
    // 1. Exchange code
    const tokenRes = await fetch(`${DISCORD_API}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  process.env.REDIRECT_URI
      })
    });
    const tokens = await tokenRes.json();
    if (!tokens.access_token) { console.error('Token exchange failed:', tokens); return res.redirect('/?error=token_failed'); }

    // 2. Fetch Discord profile
    const userRes = await fetch(`${DISCORD_API}/users/@me`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const user = await userRes.json();
    if (!user.id) return res.redirect('/?error=profile_failed');

    // 3. Check guild membership
    let isMember = false;
    if (process.env.BOT_TOKEN && process.env.GUILD_ID) {
      const memberRes = await fetch(`${DISCORD_API}/guilds/${process.env.GUILD_ID}/members/${user.id}`, {
        headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
      });
      if (memberRes.ok) {
        isMember = true;
        if (process.env.REQUIRED_ROLE_ID) {
          const md = await memberRes.json();
          isMember = md.roles.includes(process.env.REQUIRED_ROLE_ID);
        }
      }
    } else {
      isMember = true; // dev mode
    }

    const avatar = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`
      : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.id) % 5}.png`;

    // 4. Upsert user in Supabase
    const { data: existing } = await supabase.from('users').select('is_admin').eq('id', user.id).single();
    const isAdmin = isEnvAdmin(user.id) || (existing ? existing.is_admin : false);

    await supabase.from('users').upsert({
      id: user.id,
      username: user.username,
      display_name: user.global_name || user.username,
      avatar,
      is_member: isMember,
      is_admin: isAdmin,
      last_seen: new Date().toISOString()
    }, { onConflict: 'id' });

    // 5. Set session
    req.session.user = { id: user.id, username: user.username, displayName: user.global_name || user.username, avatar };
    req.session.isMember = isMember;
    req.session.isAdmin  = isAdmin;

    res.redirect(isMember ? '/' : '/?error=not_member');
  } catch (err) {
    console.error('OAuth2 callback error:', err);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/auth/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// ── API: Me ──────────────────────────────────────────────────────────────────
app.get('/api/me', async (req, res) => {
  if (!req.session.user) return res.json({ user: null, isMember: false, isAdmin: false, ownerRole: null });

  // Always re-check admin status from DB so promotions/demotions take effect without re-login
  try {
    const { data } = await supabase.from('users').select('is_admin, is_member').eq('id', req.session.user.id).single();
    if (data) {
      const isAdmin = isEnvAdmin(req.session.user.id) || data.is_admin;
      req.session.isAdmin  = isAdmin;
      req.session.isMember = data.is_member;
    }
  } catch(e) { /* ignore, use cached session */ }

  res.json({ user: req.session.user, isMember: req.session.isMember || false, isAdmin: req.session.isAdmin || false, ownerRole: null });
});

// ── API: Verify Discord username ──────────────────────────────────────────────
app.get('/api/verify-member', async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'No username provided' });
  if (!process.env.BOT_TOKEN || !process.env.GUILD_ID) return res.json({ verified: true });
  try {
    const r = await fetch(
      `${DISCORD_API}/guilds/${process.env.GUILD_ID}/members/search?query=${encodeURIComponent(username)}&limit=10`,
      { headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` } }
    );
    if (!r.ok) return res.json({ verified: false });
    const members = await r.json();
    const found = members.some(m =>
      m.user.username.toLowerCase() === username.toLowerCase() ||
      (m.user.global_name && m.user.global_name.toLowerCase() === username.toLowerCase())
    );
    res.json({ verified: found });
  } catch (err) {
    console.error('Verify member error:', err);
    res.json({ verified: false });
  }
});

// ── API: Users ────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdminApi, async (req, res) => {
  const { data, error } = await supabase.from('users').select('*').order('last_seen', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const mapped = (data || []).map(u => ({ ...u, lastSeen: u.last_seen, isMember: u.is_member, isAdmin: u.is_admin, displayName: u.display_name }));
  res.json({ users: mapped });
});

app.post('/api/users/:id/promote', requireAdminApi, async (req, res) => {
  const { error } = await supabase.from('users').update({ is_admin: true }).eq('id', req.params.id);
  if (error) return res.json({ success: false, error: error.message });
  res.json({ success: true });
});

app.post('/api/users/:id/demote', requireAdminApi, async (req, res) => {
  if (isEnvAdmin(req.params.id)) return res.json({ success: false, error: 'Cannot demote primary admin set in .env' });
  const { error } = await supabase.from('users').update({ is_admin: false }).eq('id', req.params.id);
  if (error) return res.json({ success: false, error: error.message });
  res.json({ success: true });
});

// ── API: Tournaments ──────────────────────────────────────────────────────────
app.get('/api/tournaments', async (req, res) => {
  const { data, error } = await supabase.from('tournaments').select('*').order('date', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ tournaments: data || [] });
});

app.post('/api/tournaments', requireAdminApi, async (req, res) => {
  const { title, date, status, end_date, game, max_teams, prize_pool, discord_url } = req.body;
  if (!title || !date) return res.status(400).json({ error: 'Missing required fields' });
  
  const { data, error } = await supabase.from('tournaments').insert({
    title,
    date,
    status: status || 'upcoming',
    end_date: end_date || null,
    game: game || 'mlbb',
    max_teams: max_teams ? parseInt(max_teams) : 16,
    prize_pool: prize_pool ? parseInt(prize_pool) : null,
    discord_url: discord_url || null,
    created_by: req.session.user.id
  }).select().single();
  
  if (error) return res.status(500).json({ error: error.message });
  
  // Seed the auction state for the new tournament
  await supabase.from('auction_state').insert({ tournament_id: data.id });
  
  res.json({ success: true, tournament: data });
});

app.delete('/api/tournaments/:id', requireAdminApi, async (req, res) => {
  const { error } = await supabase.from('tournaments').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/tournaments/:id', requireAdminApi, async (req, res) => {
  const allowed = ['title','status','date','end_date','game','max_teams','prize_pool','discord_url'];
  const updates = {};
  allowed.forEach(function(k) { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'No fields to update' });
  const { error } = await supabase.from('tournaments').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── API: Spots ────────────────────────────────────────────────────────────────
app.get('/api/tournaments/:id/spots', async (req, res) => {
  const { data: tourney } = await supabase.from('tournaments').select('max_teams').eq('id', req.params.id).single();
  const { data } = await supabase.from('registrations').select('id, status').eq('tournament_id', req.params.id);
  const max    = (tourney && tourney.max_teams) ? Number(tourney.max_teams) : (Number(process.env.MAX_TEAMS) || 16);
  const filled = (data || []).filter(r => r.status !== 'rejected').length;
  res.json({ filled, max });
});

// ── API: Seed Dummy Teams (admin only) ─────────────────────────────────────────
const DUMMY_TEAM_NAMES = [
  'Shadow Wolves','Neon Blades','Phantom Strike','Iron Surge','Storm Breakers',
  'Eclipse Squad','Void Rangers','Crimson Fang','Thunder Claws','Frost Giants',
  'Blaze Hunters','Dark Matter','Solar Flare','Arctic Foxes','Death Dealers',
  'Night Hawks','Steel Vipers','Chaos Theory','Dragon Force','Mystic Legends'
];
const DUMMY_PLAYERS = ['ProPlayer','Sharpshot','SwiftBlade','IronFist','StormEye'];

app.post('/api/tournaments/:id/seed-dummies', requireAdminApi, async (req, res) => {
  const { count = 8 } = req.body;
  const tournamentId = req.params.id;
  const n = Math.min(Number(count) || 8, 20);

  // Get already existing team names for this tournament to avoid dups
  const { data: existing } = await supabase.from('registrations').select('team_name').eq('tournament_id', tournamentId);
  const existingNames = new Set((existing || []).map(r => r.team_name));
  const available = DUMMY_TEAM_NAMES.filter(n => !existingNames.has(n));
  const toInsert = available.slice(0, n);

  if (!toInsert.length) return res.status(400).json({ error: 'No more dummy team names available (max 20 unique)' });

  const rows = toInsert.map((name, i) => ({
    id: Date.now().toString() + '_' + i,
    tournament_id: tournamentId,
    team_name: name,
    captain_discord_id: 'dummy_' + Date.now() + '_' + i,
    captain_username: 'dummy_user_' + i,
    players: DUMMY_PLAYERS.map((p, j) => ({ ign: p + (i+1), ingameid: String(10000 + i*5+j), discord: 'dummy' + (i*5+j) })),
    status: 'approved',
    registered_at: new Date().toISOString()
  }));

  const { error } = await supabase.from('registrations').insert(rows);
  if (error) return res.status(500).json({ error: error.message });

  // Sync newly added dummies into the auction pool immediately
  const a = await getAuction(tournamentId);
  const existingPoolIds = new Set((a.teams || []).map(t => t.id));
  const newPoolTeams = [...(a.teams || [])];
  rows.forEach(r => {
    if (!existingPoolIds.has(r.id)) {
      newPoolTeams.push({ id: r.id, name: r.team_name, logo: r.logo || null });
    }
  });
  await supabase.from('auction_state').update({ teams: newPoolTeams }).eq('tournament_id', tournamentId);

  res.json({ success: true, inserted: toInsert.length, teams: toInsert });
});

app.delete('/api/tournaments/:id/clear-dummies', requireAdminApi, async (req, res) => {
  // Dummy teams are identified by their captain_discord_id starting with 'dummy_'
  const { data: dummies } = await supabase.from('registrations').select('id').eq('tournament_id', req.params.id).like('captain_discord_id', 'dummy_%');
  if (!dummies || !dummies.length) return res.json({ success: true });
  const ids = dummies.map(d => d.id);
  const { error } = await supabase.from('registrations').delete().in('id', ids);
  if (error) return res.status(500).json({ error: error.message });

  // Also remove them from the auction pool
  const a = await getAuction(req.params.id);
  const idSet = new Set(ids);
  const filteredTeams = (a.teams || []).filter(t => !idSet.has(t.id));
  await supabase.from('auction_state').update({ teams: filteredTeams }).eq('tournament_id', req.params.id);

  res.json({ success: true });
});

// ── API: Registration ─────────────────────────────────────────────────────────
app.post('/api/register', requireMember, upload.single('logo'), async (req, res) => {
  try {
    const { teamName, players, tournamentId } = req.body;
    if (!teamName || !players || !tournamentId) return res.status(400).json({ error: 'Missing required fields' });

    const { data: existing } = await supabase.from('registrations')
      .select('id')
      .eq('captain_discord_id', req.session.user.id)
      .eq('tournament_id', tournamentId)
      .single();
      
    if (existing) return res.status(400).json({ error: 'You have already registered a team for this tournament.' });

    let parsedPlayers;
    try { parsedPlayers = JSON.parse(players); } catch { return res.status(400).json({ error: 'Invalid player data' }); }

    const team = {
      id: Date.now().toString(),
      tournament_id: tournamentId,
      team_name: teamName.trim(),
      captain_discord_id: req.session.user.id,
      captain_username: req.session.user.username,
      players: parsedPlayers,
      logo: req.file ? `/uploads/${req.file.filename}` : null,
      status: 'pending',
      registered_at: new Date().toISOString()
    };

    const { error } = await supabase.from('registrations').insert(team);
    if (error) throw error;
    res.json({ success: true, team: teamToFE(team) });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/my-team/:tournamentId', requireAuth, async (req, res) => {
  const { data } = await supabase.from('registrations')
    .select('*')
    .eq('captain_discord_id', req.session.user.id)
    .eq('tournament_id', req.params.tournamentId)
    .single();
  res.json({ team: data ? teamToFE(data) : null });
});

// ── API: Admin — Teams ────────────────────────────────────────────────────────

// Public read of approved teams for the hub (no auth required)
app.get('/api/teams/:tournamentId/approved', async (req, res) => {
  const { data, error } = await supabase.from('registrations').select('id,team_name,logo,players,status').eq('tournament_id', req.params.tournamentId).eq('status', 'approved').order('registered_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ teams: (data || []).map(t => ({ ...t, teamName: t.team_name })) });
});

app.get('/api/teams/:tournamentId', requireAdminApi, async (req, res) => {
  const { data, error } = await supabase.from('registrations').select('*').eq('tournament_id', req.params.tournamentId).order('registered_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ teams: (data || []).map(teamToFE) });
});

app.post('/api/teams/:id/approve', requireAdminApi, async (req, res) => {
  const { data: team, error } = await supabase.from('registrations').update({ status: 'approved' }).eq('id', req.params.id).select().single();
  if (error) return res.status(404).json({ error: error.message });

  // Sync to auction pool
  const a = await getAuction(team.tournament_id);
  const teams = a.teams || [];
  if (!teams.find(t => t.id === team.id)) {
    teams.push({ id: team.id, name: team.team_name, logo: team.logo });
    await supabase.from('auction_state').update({ teams }).eq('tournament_id', team.tournament_id);
  }
  res.json({ success: true });
});

app.post('/api/teams/:id/reject', requireAdminApi, async (req, res) => {
  const { error } = await supabase.from('registrations').update({ status: 'rejected' }).eq('id', req.params.id);
  if (error) return res.status(404).json({ error: error.message });
  res.json({ success: true });
});

app.delete('/api/teams/:id', requireAdminApi, async (req, res) => {
  const { error } = await supabase.from('registrations').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── API: Auction ──────────────────────────────────────────────────────────────

// Public read — any logged-in user (or even anonymous) can watch the live state
// Also returns ownerRole (1 or 2) if the logged-in user is a configured owner
app.get('/api/auction/state/:tournamentId', async (req, res) => {
  const a = await getAuction(req.params.tournamentId);
  const fe = toFE(a);
  // Attach ownerRole so frontend can show/hide the correct bid panel
  let ownerRole = null;
  if (req.session.user) {
    const uname = req.session.user.username.toLowerCase();
    if (a.owner1 && a.owner1.discord && a.owner1.discord.toLowerCase() === uname) ownerRole = 1;
    else if (a.owner2 && a.owner2.discord && a.owner2.discord.toLowerCase() === uname) ownerRole = 2;
  }
  fe.ownerRole = ownerRole;
  res.json(fe);
});

app.post('/api/auction/bid', async (req, res) => {
  // Allow if admin OR if the session user is the configured owner for that slot
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  const { owner, amount, tournamentId } = req.body;
  const a = await getAuction(tournamentId);

  // Check permission: admin can bid for either; owners can only bid for their own slot
  const isAdmin = req.session.isAdmin;
  const uname   = req.session.user.username.toLowerCase();
  const ownerKey = `owner${owner}`;
  const ownerData = a[ownerKey];
  if (!ownerData) return res.status(400).json({ error: 'Invalid owner' });

  const ownerDiscord = (ownerData.discord || '').toLowerCase();
  const isMatchingOwner = ownerDiscord && ownerDiscord === uname;
  if (!isAdmin && !isMatchingOwner) return res.status(403).json({ error: 'You are not authorised to bid for this owner' });

  if (a.concluded) return res.status(400).json({ error: 'Auction is concluded' });
  if (!a.teams.length || a.current_index >= a.teams.length) return res.status(400).json({ error: 'No teams left' });
  if (a.current_bidder_id === Number(owner)) return res.status(400).json({ error: 'You are already the highest bidder' });

  const newBid = a.current_bid + Number(amount);
  if (newBid > ownerData.points) return res.status(400).json({ error: 'Not enough points' });

  const { error } = await supabase.from('auction_state').update({ current_bid: newBid, current_bidder_id: Number(owner), started: true, bid_at: new Date().toISOString() }).eq('tournament_id', tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, auction: toFE({ ...a, current_bid: newBid, current_bidder_id: Number(owner), started: true, bid_at: new Date().toISOString() }) });
});

app.post('/api/auction/sold', requireAdminApi, async (req, res) => {
  const { tournamentId } = req.body;
  const a = await getAuction(tournamentId);
  if (!a.current_bidder_id) return res.status(400).json({ error: 'No bids placed yet' });

  const ownerKey = `owner${a.current_bidder_id}`;
  const ownerData = { ...a[ownerKey], roster: [...(a[ownerKey].roster || []), { ...a.teams[a.current_index], soldFor: a.current_bid }] };
  ownerData.points -= a.current_bid;

  const newIndex  = a.current_index + 1;
  const concluded = newIndex >= a.teams.length;

  const { error } = await supabase.from('auction_state').update({
    current_index: newIndex, current_bid: 0, current_bidder_id: null, concluded, [ownerKey]: ownerData, bid_at: null
  }).eq('tournament_id', tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, auction: toFE({ ...a, current_index: newIndex, current_bid: 0, current_bidder_id: null, concluded, [ownerKey]: ownerData, bid_at: null }) });
});

app.post('/api/auction/skip', requireAdminApi, async (req, res) => {
  const { tournamentId } = req.body;
  const a = await getAuction(tournamentId);
  const newIndex  = a.current_index + 1;
  const concluded = newIndex >= a.teams.length;
  const { error } = await supabase.from('auction_state').update({ current_index: newIndex, current_bid: 0, current_bidder_id: null, concluded, bid_at: null }).eq('tournament_id', tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, auction: toFE({ ...a, current_index: newIndex, current_bid: 0, current_bidder_id: null, concluded, bid_at: null }) });
});

app.post('/api/auction/config', requireAdminApi, async (req, res) => {
  const { tournamentId, owner1Name, owner2Name, owner1Discord, owner2Discord } = req.body;
  if (!tournamentId) return res.status(400).json({ error: 'tournamentId required' });
  const a = await getAuction(tournamentId);
  const updates = {};
  if (owner1Name || owner1Discord !== undefined) {
    updates.owner1 = { ...a.owner1 };
    if (owner1Name)              updates.owner1.name    = owner1Name;
    if (owner1Discord !== undefined) updates.owner1.discord = owner1Discord.trim().toLowerCase();
  }
  if (owner2Name || owner2Discord !== undefined) {
    updates.owner2 = { ...a.owner2 };
    if (owner2Name)              updates.owner2.name    = owner2Name;
    if (owner2Discord !== undefined) updates.owner2.discord = owner2Discord.trim().toLowerCase();
  }
  const { error } = await supabase.from('auction_state').update(updates).eq('tournament_id', tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, auction: toFE({ ...a, ...updates }) });
});

app.post('/api/auction/reset', requireAdminApi, async (req, res) => {
  const { tournamentId, startingPoints, owner1Name, owner2Name, owner1Discord, owner2Discord } = req.body;
  const pts = Number(startingPoints) || 100000;
  const a = await getAuction(tournamentId); // preserve existing discord if not re-supplied
  const { data: approved } = await supabase.from('registrations').select('*').eq('status', 'approved').eq('tournament_id', tournamentId);
  const fresh = {
    teams: (approved || []).map(t => ({ id: t.id, name: t.team_name, logo: t.logo })),
    current_index: 0, current_bid: 0, current_bidder_id: null,
    owner1: { name: owner1Name || a.owner1?.name || 'Owner 1', discord: (owner1Discord !== undefined ? owner1Discord.trim().toLowerCase() : (a.owner1?.discord || '')), points: pts, roster: [] },
    owner2: { name: owner2Name || a.owner2?.name || 'Owner 2', discord: (owner2Discord !== undefined ? owner2Discord.trim().toLowerCase() : (a.owner2?.discord || '')), points: pts, roster: [] },
    started: false, concluded: false,
    bracket: null  // clear bracket on reset so it gets regenerated from new rosters
  };
  const { error } = await supabase.from('auction_state').update(fresh).eq('tournament_id', tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, auction: toFE({ ...fresh, tournament_id: tournamentId }) });
});

// ── API: Bracket ──────────────────────────────────────────────────────────────

// Shuffle array in place (Fisher-Yates)
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// Next power of 2 >= n
function nextPow2(n) {
  let p = 1; while (p < n) p <<= 1; return p;
}

/*
  Seeding rule:
  - Round 1: interleave Owner1 and Owner2 teams so every R1 match is O1 vs O2
  - If counts are uneven, the extra teams from one owner play each other first,
    then the remainder are interleaved
  - Byes fill slots so total = next power of 2
*/
function generateBracket(owner1Name, owner1Roster, owner2Name, owner2Roster) {
  // Annotate each team with its owner
  const o1 = shuffle(owner1Roster.map(t => ({ id: t.id, name: t.name, logo: t.logo || null, owner: 1, ownerName: owner1Name })));
  const o2 = shuffle(owner2Roster.map(t => ({ id: t.id, name: t.name, logo: t.logo || null, owner: 2, ownerName: owner2Name })));

  // Build seeds array: interleave O1/O2, excess goes at the end
  const seeds = [];
  const minLen = Math.min(o1.length, o2.length);
  for (let i = 0; i < minLen; i++) { seeds.push(o1[i]); seeds.push(o2[i]); }
  const extra = o1.length > o2.length ? o1.slice(minLen) : o2.slice(minLen);
  extra.forEach(t => seeds.push(t));

  // Pad to next power of 2 with BYE slots
  const size = nextPow2(seeds.length);
  const totalTeams = seeds.length; // real team count before padding
  while (seeds.length < size) seeds.push(null); // null = BYE

  // ── Build all rounds as shells ──────────────────────────────────────────
  const rounds = [];

  // Round 1 — fill from seeds
  const r1Matches = [];
  for (let i = 0; i < size; i += 2) {
    r1Matches.push({ id: `r1m${i/2}`, team1: seeds[i], team2: seeds[i + 1], winner: null, bye: false });
  }
  rounds.push({ round: 1, label: 'Round 1', matches: r1Matches });

  // Subsequent round shells
  let prevCount = r1Matches.length;
  let roundNum  = 2;
  while (prevCount > 1) {
    const count   = prevCount / 2;
    const labels  = { [size / 2]: 'Quarterfinals', 2: 'Semifinals', 1: 'Final' };
    const label   = labels[count] || `Round ${roundNum}`;
    const matches = [];
    for (let i = 0; i < count; i++) {
      matches.push({ id: `r${roundNum}m${i}`, team1: null, team2: null, winner: null, bye: false });
    }
    rounds.push({ round: roundNum, label, matches });
    prevCount = count;
    roundNum++;
  }

  // ── Auto-advance BYE matches ────────────────────────────────────────────
  // Any R1 match where one slot is null (BYE) → the real team auto-wins
  // and is propagated to round 2 immediately. The BYE match is flagged
  // so the frontend can hide it cleanly.
  rounds[0].matches.forEach((match, mIdx) => {
    const hasBye = match.team1 === null || match.team2 === null;
    if (!hasBye) return;

    const realTeam = match.team1 || match.team2;
    if (!realTeam) return; // both null — double BYE, skip

    match.winner = realTeam;
    match.bye    = true; // flag so UI can hide or dim

    // Advance winner into round 2
    if (rounds.length > 1) {
      const nextMatchIdx = Math.floor(mIdx / 2);
      const nextMatch    = rounds[1].matches[nextMatchIdx];
      if (nextMatch) {
        if (mIdx % 2 === 0) nextMatch.team1 = realTeam;
        else                 nextMatch.team2 = realTeam;
      }
    }
  });

  // Recalculate round labels now that we know actual matchup sizes
  // (size/2 may now be wrong label-wise for small brackets)
  const realR1 = rounds[0].matches.filter(m => !m.bye).length;
  const roundLabels = {
    1: realR1 <= 4 ? 'Semifinals' : realR1 <= 8 ? 'Quarterfinals' : 'Round 1',
  };
  rounds.forEach((r, i) => {
    if (i === 0) { r.label = roundLabels[1] || 'Round 1'; }
    else {
      const mc = r.matches.length;
      r.label = mc === 1 ? 'Final' : mc === 2 ? 'Semifinals' : mc <= 4 ? 'Quarterfinals' : `Round ${r.round}`;
    }
  });

  return { rounds, generated: new Date().toISOString(), size, totalTeams };
}

// Public read of bracket
app.get('/api/bracket/:tournamentId', async (req, res) => {
  const a = await getAuction(req.params.tournamentId);
  res.json({ bracket: a.bracket || null });
});

// Admin: generate/regenerate bracket from current rosters
app.post('/api/bracket/generate/:tournamentId', requireAdminApi, async (req, res) => {
  const a = await getAuction(req.params.tournamentId);
  const o1Roster = (a.owner1 && a.owner1.roster) || [];
  const o2Roster = (a.owner2 && a.owner2.roster) || [];
  if (o1Roster.length + o2Roster.length < 2) {
    return res.status(400).json({ error: 'Need at least 2 teams drafted to generate a bracket' });
  }
  const bracket = generateBracket(
    (a.owner1 && a.owner1.name) || 'Owner 1', o1Roster,
    (a.owner2 && a.owner2.name) || 'Owner 2', o2Roster
  );
  const { error } = await supabase.from('auction_state').update({ bracket }).eq('tournament_id', req.params.tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, bracket });
});

// Admin: record a match result and advance the winner
app.post('/api/bracket/result/:tournamentId', requireAdminApi, async (req, res) => {
  const { roundIndex, matchIndex, winnerId } = req.body;
  const a = await getAuction(req.params.tournamentId);
  if (!a.bracket) return res.status(400).json({ error: 'No bracket generated yet' });

  const bracket = JSON.parse(JSON.stringify(a.bracket)); // deep clone
  const match   = bracket.rounds[roundIndex] && bracket.rounds[roundIndex].matches[matchIndex];
  if (!match) return res.status(400).json({ error: 'Match not found' });

  // Find and set winner
  const winner = (match.team1 && match.team1.id === winnerId) ? match.team1
               : (match.team2 && match.team2.id === winnerId) ? match.team2
               : null;
  if (!winner) return res.status(400).json({ error: 'Winner ID not in this match' });
  match.winner = winner;

  // Advance winner to the next round
  const nextRound = bracket.rounds[roundIndex + 1];
  if (nextRound) {
    const nextMatchIndex = Math.floor(matchIndex / 2);
    const nextMatch = nextRound.matches[nextMatchIndex];
    if (nextMatch) {
      if (matchIndex % 2 === 0) nextMatch.team1 = winner;
      else                       nextMatch.team2 = winner;
    }
  }

  const { error } = await supabase.from('auction_state').update({ bracket }).eq('tournament_id', req.params.tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, bracket });
});

// Admin: clear/edit a match result — removes winner and clears that team from next round
app.post('/api/bracket/clear-result/:tournamentId', requireAdminApi, async (req, res) => {
  const { roundIndex, matchIndex } = req.body;
  const a = await getAuction(req.params.tournamentId);
  if (!a.bracket) return res.status(400).json({ error: 'No bracket generated yet' });

  const bracket = JSON.parse(JSON.stringify(a.bracket));
  const match   = bracket.rounds[roundIndex] && bracket.rounds[roundIndex].matches[matchIndex];
  if (!match) return res.status(400).json({ error: 'Match not found' });

  const prevWinner = match.winner;
  match.winner = null;

  // Remove the previous winner from the next round slot it occupied
  if (prevWinner) {
    const nextRound = bracket.rounds[roundIndex + 1];
    if (nextRound) {
      const nextMatchIndex = Math.floor(matchIndex / 2);
      const nextMatch = nextRound.matches[nextMatchIndex];
      if (nextMatch) {
        // Clear winner of the next round match too (cascade one level)
        if (nextMatch.winner && nextMatch.winner.id === prevWinner.id) {
          nextMatch.winner = null;
          // Also clear from the round after that
          const nextNextRound = bracket.rounds[roundIndex + 2];
          if (nextNextRound) {
            const nnMatchIdx = Math.floor(nextMatchIndex / 2);
            const nnMatch = nextNextRound.matches[nnMatchIdx];
            if (nnMatch) {
              if (nnMatch.team1 && nnMatch.team1.id === prevWinner.id) nnMatch.team1 = null;
              if (nnMatch.team2 && nnMatch.team2.id === prevWinner.id) nnMatch.team2 = null;
              if (nnMatch.winner && nnMatch.winner.id === prevWinner.id) nnMatch.winner = null;
            }
          }
        }
        // Clear from next match slots
        if (nextMatch.team1 && nextMatch.team1.id === prevWinner.id) nextMatch.team1 = null;
        if (nextMatch.team2 && nextMatch.team2.id === prevWinner.id) nextMatch.team2 = null;
      }
    }
  }

  const { error } = await supabase.from('auction_state').update({ bracket }).eq('tournament_id', req.params.tournamentId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, bracket });
});

// ── Protected page routes ─────────────────────────────────────────────────────
// Everything is served from index.html now; legacy URLs redirect back home
app.get('/admin',   (req, res) => res.redirect('/'));
app.get('/auction', (req, res) => res.redirect('/'));

// PWA icon fallback — serve SVG for icon requests if PNG not present
app.get('/icons/:size.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'icons', 'icon.svg'), {
    headers: { 'Content-Type': 'image/svg+xml' }
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║   🎮  ICEBERG Showdown — Auction Platform        ║');
  console.log(`║   Running at: http://localhost:${PORT}             ║`);
  console.log('║                                                  ║');
  console.log('║   Backend: Supabase ✅                           ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
  if (!process.env.SUPABASE_URL) console.log('⚠️  WARNING: SUPABASE_URL not set!');
});
