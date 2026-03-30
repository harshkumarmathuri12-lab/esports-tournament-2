-- =============================================================================
-- Esports Tournament App - Supabase Schema (Single Run)
-- =============================================================================
-- Run this ONCE in Supabase SQL Editor on a fresh project.
-- Paste the entire file and execute. Tables, RLS, triggers, and seed data will
-- be created. Safe to re-run storage policies and trigger (uses DROP IF EXISTS).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- 001: Initial Schema
-- =============================================================================

-- Users table (extends Supabase auth.users)
CREATE TABLE public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  display_name TEXT,
  in_game_name TEXT,
  in_game_uid TEXT,
  coins INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Admins table (adminname + password credentials; user_id optional for future link)
CREATE TABLE public.admins (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  adminname TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Games table
CREATE TABLE public.games (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  image_url TEXT,
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Game modes table
CREATE TABLE public.game_modes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  game_id UUID NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  image_url TEXT,
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Matches table
CREATE TABLE public.matches (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  game_mode_id UUID NOT NULL REFERENCES public.game_modes(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  entry_fee INTEGER NOT NULL DEFAULT 0,
  room_code TEXT,
  room_password TEXT,
  status TEXT NOT NULL DEFAULT 'upcoming' CHECK (status IN ('upcoming', 'ongoing', 'completed', 'ended')),
  registration_locked BOOLEAN DEFAULT FALSE,
  max_participants INTEGER DEFAULT 100,
  starts_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Match participants (users who joined a match)
CREATE TABLE public.match_participants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  match_id UUID NOT NULL REFERENCES public.matches(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  in_game_name TEXT NOT NULL,
  in_game_uid TEXT NOT NULL,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(match_id, user_id)
);

-- Coin transactions (for audit trail)
CREATE TABLE public.coin_transactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('admin_add', 'match_entry', 'refund')),
  reference_id UUID,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- RLS Policies
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.games ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.game_modes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.match_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.coin_transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own profile" ON public.users
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON public.users
  FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Admins can read all users" ON public.users
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );
CREATE POLICY "Admins can update all users" ON public.users
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

CREATE POLICY "Admins can read admins" ON public.admins
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins a WHERE a.user_id = auth.uid())
  );

CREATE POLICY "Anyone can read games" ON public.games
  FOR SELECT USING (true);
CREATE POLICY "Admins can manage games" ON public.games
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

CREATE POLICY "Anyone can read game modes" ON public.game_modes
  FOR SELECT USING (true);
CREATE POLICY "Admins can manage game modes" ON public.game_modes
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

CREATE POLICY "Anyone can read matches" ON public.matches
  FOR SELECT USING (true);
CREATE POLICY "Admins can manage matches" ON public.matches
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

CREATE POLICY "Users can read match participants" ON public.match_participants
  FOR SELECT USING (true);
CREATE POLICY "Users can insert own participation" ON public.match_participants
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can read own transactions" ON public.coin_transactions
  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Admins can manage transactions" ON public.coin_transactions
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

-- Function to create user profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.users (id, email)
  VALUES (NEW.id, NEW.email);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Storage bucket for game/mode images
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM storage.buckets WHERE id = 'images') THEN
    INSERT INTO storage.buckets (id, name, public) VALUES ('images', 'images', true);
  END IF;
END $$;

DROP POLICY IF EXISTS "Public read for images" ON storage.objects;
CREATE POLICY "Public read for images" ON storage.objects
  FOR SELECT USING (bucket_id = 'images');
CREATE POLICY "Admins can upload images" ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );
CREATE POLICY "Admins can update images" ON storage.objects
  FOR UPDATE USING (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );
CREATE POLICY "Admins can delete images" ON storage.objects
  FOR DELETE USING (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

-- =============================================================================
-- 002: Admin Permissions
-- =============================================================================

ALTER TABLE public.admins
  ADD COLUMN IF NOT EXISTS is_master_admin BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS users_access BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS coins_access BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS games_access_type TEXT NOT NULL DEFAULT 'all' CHECK (games_access_type IN ('all', 'specific'));

CREATE TABLE IF NOT EXISTS public.admin_allowed_games (
  admin_id UUID NOT NULL REFERENCES public.admins(id) ON DELETE CASCADE,
  game_id UUID NOT NULL REFERENCES public.games(id) ON DELETE CASCADE,
  PRIMARY KEY (admin_id, game_id)
);

ALTER TABLE public.admin_allowed_games ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Master admins can manage admin_allowed_games" ON public.admin_allowed_games
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND is_master_admin = TRUE)
  );
CREATE POLICY "Admins can read own allowed games" ON public.admin_allowed_games
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.admins a
      WHERE a.user_id = auth.uid()
      AND (a.id = admin_allowed_games.admin_id OR a.is_master_admin = TRUE)
    )
  );

DROP POLICY IF EXISTS "Admins can read admins" ON public.admins;
CREATE POLICY "Master admins can read all admins" ON public.admins
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND is_master_admin = TRUE)
  );
CREATE POLICY "Admins can read own admin row" ON public.admins
  FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "Master admins can insert admins" ON public.admins
  FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND is_master_admin = TRUE)
  );
CREATE POLICY "Master admins can update admins" ON public.admins
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND is_master_admin = TRUE)
  );
CREATE POLICY "Master admins can delete admins" ON public.admins
  FOR DELETE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND is_master_admin = TRUE)
  );

DROP POLICY IF EXISTS "Admins can read all users" ON public.users;
DROP POLICY IF EXISTS "Admins can update all users" ON public.users;
CREATE POLICY "Admins with users_access can read all users" ON public.users
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND users_access = TRUE)
  );
CREATE POLICY "Admins with users_access can update all users" ON public.users
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND users_access = TRUE)
  );

DROP POLICY IF EXISTS "Admins can manage games" ON public.games;
CREATE POLICY "Admins can manage games" ON public.games
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.admins a
      WHERE a.user_id = auth.uid()
      AND (
        a.is_master_admin = TRUE
        OR a.games_access_type = 'all'
        OR EXISTS (SELECT 1 FROM public.admin_allowed_games ag WHERE ag.admin_id = a.id AND ag.game_id = games.id)
      )
    )
  );

DROP POLICY IF EXISTS "Admins can manage game_modes" ON public.game_modes;
CREATE POLICY "Admins can manage game_modes" ON public.game_modes
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.admins a
      WHERE a.user_id = auth.uid()
      AND (
        a.is_master_admin = TRUE
        OR a.games_access_type = 'all'
        OR EXISTS (SELECT 1 FROM public.admin_allowed_games ag WHERE ag.admin_id = a.id AND ag.game_id = game_modes.game_id)
      )
    )
  );

DROP POLICY IF EXISTS "Admins can manage matches" ON public.matches;
CREATE POLICY "Admins can manage matches" ON public.matches
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.admins a
      JOIN public.game_modes gm ON gm.id = matches.game_mode_id
      WHERE a.user_id = auth.uid()
      AND (
        a.is_master_admin = TRUE
        OR a.games_access_type = 'all'
        OR EXISTS (SELECT 1 FROM public.admin_allowed_games ag WHERE ag.admin_id = a.id AND ag.game_id = gm.game_id)
      )
    )
  );

DROP POLICY IF EXISTS "Admins can manage transactions" ON public.coin_transactions;
CREATE POLICY "Admins with coins_access can manage transactions" ON public.coin_transactions
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );

DROP POLICY IF EXISTS "Admins can upload images" ON storage.objects;
DROP POLICY IF EXISTS "Admins can update images" ON storage.objects;
DROP POLICY IF EXISTS "Admins can delete images" ON storage.objects;
CREATE POLICY "Admins can upload images" ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );
CREATE POLICY "Admins can update images" ON storage.objects
  FOR UPDATE USING (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );
CREATE POLICY "Admins can delete images" ON storage.objects
  FOR DELETE USING (
    bucket_id = 'images' AND
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid())
  );

-- =============================================================================
-- 003: Admin adminname credentials (adminname/password_hash already in 001; skip if exists)
-- =============================================================================

-- Make user_id nullable for adminname-only auth (no-op if already nullable)
DO $$ BEGIN
  ALTER TABLE public.admins ALTER COLUMN user_id DROP NOT NULL;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- =============================================================================
-- 004: Coin transactions indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_coin_transactions_user_id_created_at
  ON public.coin_transactions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_coin_transactions_created_at
  ON public.coin_transactions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_coin_transactions_type
  ON public.coin_transactions (type);

-- =============================================================================
-- 005: Match type and team members
-- =============================================================================

ALTER TABLE public.matches
  ADD COLUMN IF NOT EXISTS match_type TEXT NOT NULL DEFAULT 'solo'
  CHECK (match_type IN ('solo', 'duo', 'squad'));

ALTER TABLE public.match_participants
  ADD COLUMN IF NOT EXISTS participant_2_name TEXT,
  ADD COLUMN IF NOT EXISTS participant_2_uid TEXT,
  ADD COLUMN IF NOT EXISTS participant_3_name TEXT,
  ADD COLUMN IF NOT EXISTS participant_3_uid TEXT,
  ADD COLUMN IF NOT EXISTS participant_4_name TEXT,
  ADD COLUMN IF NOT EXISTS participant_4_uid TEXT;

-- =============================================================================
-- 006: Prize pool and results
-- =============================================================================

ALTER TABLE public.matches
  ADD COLUMN IF NOT EXISTS coins_per_kill INTEGER DEFAULT 5,
  ADD COLUMN IF NOT EXISTS rank_rewards JSONB DEFAULT '[]'::jsonb;

ALTER TABLE public.match_participants
  ADD COLUMN IF NOT EXISTS squad_rank INTEGER,
  ADD COLUMN IF NOT EXISTS coins_won INTEGER,
  ADD COLUMN IF NOT EXISTS kills INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS participant_2_kills INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS participant_3_kills INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS participant_4_kills INTEGER DEFAULT 0;

-- =============================================================================
-- 007: Deposits and app updates
-- =============================================================================

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE;

ALTER TABLE public.matches DROP CONSTRAINT IF EXISTS matches_status_check;
ALTER TABLE public.matches ADD CONSTRAINT matches_status_check
  CHECK (status IN ('upcoming', 'ongoing', 'completed', 'ended', 'cancelled'));

ALTER TABLE public.coin_transactions DROP CONSTRAINT IF EXISTS coin_transactions_type_check;
ALTER TABLE public.coin_transactions ADD CONSTRAINT coin_transactions_type_check
  CHECK (type IN ('admin_add', 'match_entry', 'refund', 'deposit', 'deposit_failed'));

ALTER TABLE public.coin_transactions
  ADD COLUMN IF NOT EXISTS reference_text TEXT;

CREATE TABLE IF NOT EXISTS public.deposit_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK (amount > 0),
  utr TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deposit_requests_status ON public.deposit_requests (status);
CREATE INDEX IF NOT EXISTS idx_deposit_requests_user_id ON public.deposit_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_deposit_requests_created_at ON public.deposit_requests (created_at DESC);

ALTER TABLE public.deposit_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins with coins_access can read deposit_requests" ON public.deposit_requests
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Admins with coins_access can update deposit_requests" ON public.deposit_requests
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Users can insert own deposit request" ON public.deposit_requests
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.app_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public can read app_settings" ON public.app_settings
  FOR SELECT USING (true);
CREATE POLICY "Admins with coins_access can manage app_settings" ON public.app_settings
  FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Admins with coins_access can update app_settings" ON public.app_settings
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Admins with coins_access can delete app_settings" ON public.app_settings
  FOR DELETE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );

-- =============================================================================
-- 008: Withdrawals, signup bonus
-- =============================================================================

ALTER TABLE public.coin_transactions DROP CONSTRAINT IF EXISTS coin_transactions_type_check;
ALTER TABLE public.coin_transactions ADD CONSTRAINT coin_transactions_type_check
  CHECK (type IN (
    'admin_add', 'match_entry', 'refund', 'deposit', 'deposit_failed',
    'withdraw', 'withdraw_failed', 'signup_bonus'
  ));

CREATE TABLE IF NOT EXISTS public.withdrawal_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK (amount > 0),
  upi_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  charge_percent NUMERIC(5,2) DEFAULT 0 CHECK (charge_percent >= 0 AND charge_percent <= 100),
  reject_note TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON public.withdrawal_requests (status);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON public.withdrawal_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_created_at ON public.withdrawal_requests (created_at DESC);

ALTER TABLE public.withdrawal_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins with coins_access can read withdrawal_requests" ON public.withdrawal_requests
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Admins with coins_access can update withdrawal_requests" ON public.withdrawal_requests
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.admins WHERE user_id = auth.uid() AND coins_access = TRUE)
  );
CREATE POLICY "Users can insert own withdrawal request" ON public.withdrawal_requests
  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can read own withdrawal requests" ON public.withdrawal_requests
  FOR SELECT USING (auth.uid() = user_id);

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS user_number TEXT UNIQUE;

CREATE INDEX IF NOT EXISTS idx_users_user_number ON public.users (user_number);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users (LOWER(email));

CREATE OR REPLACE FUNCTION public.generate_user_number()
RETURNS TEXT AS $$
DECLARE
  new_num TEXT;
  exists_check BOOLEAN;
BEGIN
  LOOP
    new_num := LPAD(FLOOR(10000 + RANDOM() * 90000)::TEXT, 5, '0');
    SELECT EXISTS(SELECT 1 FROM public.users WHERE user_number = new_num) INTO exists_check;
    EXIT WHEN NOT exists_check;
  END LOOP;
  RETURN new_num;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  bonus INTEGER := 0;
BEGIN
  SELECT COALESCE((SELECT value::INTEGER FROM public.app_settings WHERE key = 'signup_bonus' LIMIT 1), 0) INTO bonus;

  INSERT INTO public.users (id, email, display_name, user_number, coins)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(SPLIT_PART(NEW.email, '@', 1), 'User'),
    public.generate_user_number(),
    GREATEST(0, bonus)
  );

  IF bonus > 0 THEN
    INSERT INTO public.coin_transactions (user_id, amount, type, description)
    VALUES (NEW.id, bonus, 'signup_bonus', 'Signup bonus');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- 009: App users (custom auth flow)
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.app_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT 'User',
  coins INTEGER NOT NULL DEFAULT 0,
  is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_users_email_lower ON public.app_users (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_app_users_created_at ON public.app_users (created_at DESC);

CREATE TABLE IF NOT EXISTS public.app_coin_transactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id TEXT NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  type TEXT NOT NULL CHECK (type IN (
    'admin_add', 'match_entry', 'refund', 'deposit', 'deposit_failed',
    'withdraw', 'withdraw_failed', 'signup_bonus', 'match_winning'
  )),
  reference_id TEXT,
  reference_text TEXT,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_coin_transactions_user_id ON public.app_coin_transactions (user_id);
CREATE INDEX IF NOT EXISTS idx_app_coin_transactions_created_at ON public.app_coin_transactions (created_at DESC);

CREATE TABLE IF NOT EXISTS public.app_deposit_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id TEXT NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK (amount > 0),
  utr TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_deposit_requests_status ON public.app_deposit_requests (status);
CREATE INDEX IF NOT EXISTS idx_app_deposit_requests_user_id ON public.app_deposit_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_app_deposit_requests_created_at ON public.app_deposit_requests (created_at DESC);

CREATE TABLE IF NOT EXISTS public.app_withdrawal_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id TEXT NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK (amount > 0),
  upi_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  charge_percent NUMERIC(5,2) DEFAULT 0 CHECK (charge_percent >= 0 AND charge_percent <= 100),
  reject_note TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_withdrawal_requests_status ON public.app_withdrawal_requests (status);
CREATE INDEX IF NOT EXISTS idx_app_withdrawal_requests_user_id ON public.app_withdrawal_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_app_withdrawal_requests_created_at ON public.app_withdrawal_requests (created_at DESC);

CREATE OR REPLACE FUNCTION public.generate_app_user_id()
RETURNS TEXT AS $$
DECLARE
  new_id TEXT;
  exists_check BOOLEAN;
BEGIN
  LOOP
    new_id := LPAD(FLOOR(10000 + RANDOM() * 90000)::TEXT, 5, '0');
    SELECT EXISTS(SELECT 1 FROM public.app_users WHERE id = new_id) INTO exists_check;
    EXIT WHEN NOT exists_check;
  END LOOP;
  RETURN new_id;
END;
$$ LANGUAGE plpgsql;

INSERT INTO public.app_settings (key, value, updated_at)
VALUES
  ('signup_bonus', '0', NOW()),
  ('withdrawal_charge', '0', NOW()),
  ('deposit_qr_url', '', NOW()),
  ('customer_support_url', '', NOW())
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.admins (adminname, password_hash, is_master_admin, users_access, coins_access, games_access_type)
SELECT 'masteradmin', '$2b$10$FBJKxjXVVYsKXA9ChWsIfuW.3MTWBjsySWzrjgsaBFvj1m0.xtdbO', TRUE, TRUE, TRUE, 'all'
WHERE NOT EXISTS (SELECT 1 FROM public.admins LIMIT 1);

ALTER TABLE public.app_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_coin_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_deposit_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_withdrawal_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access app_users" ON public.app_users
  FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access app_coin_transactions" ON public.app_coin_transactions
  FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access app_deposit_requests" ON public.app_deposit_requests
  FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access app_withdrawal_requests" ON public.app_withdrawal_requests
  FOR ALL USING (auth.role() = 'service_role');

-- =============================================================================
-- 010: Total prize pool
-- =============================================================================

ALTER TABLE public.matches
  ADD COLUMN IF NOT EXISTS total_prize_pool INTEGER DEFAULT 0;

-- Run in Supabase SQL Editor if uploads still fail
DROP POLICY IF EXISTS "Service role can manage images" ON storage.objects;
CREATE POLICY "Service role can manage images"
ON storage.objects FOR ALL
USING (auth.role() = 'service_role');

ALTER TABLE public.app_users
  ADD COLUMN IF NOT EXISTS fcm_token TEXT;

CREATE INDEX IF NOT EXISTS idx_app_users_fcm_token ON public.app_users (fcm_token) WHERE fcm_token IS NOT NULL;

-- =============================================================================
-- 011: App match participants (for app_users joining matches)
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.app_match_participants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  match_id UUID NOT NULL REFERENCES public.matches(id) ON DELETE CASCADE,
  app_user_id TEXT NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
  in_game_name TEXT NOT NULL,
  in_game_uid TEXT NOT NULL,
  participant_2_name TEXT,
  participant_2_uid TEXT,
  participant_3_name TEXT,
  participant_3_uid TEXT,
  participant_4_name TEXT,
  participant_4_uid TEXT,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(match_id, app_user_id)
);

CREATE INDEX IF NOT EXISTS idx_app_match_participants_match ON public.app_match_participants (match_id);
CREATE INDEX IF NOT EXISTS idx_app_match_participants_user ON public.app_match_participants (app_user_id);

ALTER TABLE public.app_match_participants ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access app_match_participants" ON public.app_match_participants
  FOR ALL USING (auth.role() = 'service_role');

-- Add kills and squad_rank for admin to update during ongoing matches
ALTER TABLE public.app_match_participants
  ADD COLUMN IF NOT EXISTS kills INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS squad_rank INTEGER;

-- =============================================================================
-- 012: App users password (for email+password auth)
-- =============================================================================

ALTER TABLE public.app_users
  ADD COLUMN IF NOT EXISTS password_hash TEXT;