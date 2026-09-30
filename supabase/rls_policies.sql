-- ============================================================================
-- Row Level Security (RLS) Policies for Essential Lanka
-- ============================================================================
-- This file implements comprehensive RLS policies for all database tables.
-- RLS ensures users can only access data they're authorized to see.
--
-- Security Model:
-- - Users can only see their own profile data
-- - Clients can see their own jobs and related bids/payments
-- - Workers can see jobs they've bid on or been assigned to
-- - Admins can see everything
-- - Public data: categories (read-only)
-- ============================================================================

-- Enable Row Level Security on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE worker_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_images ENABLE ROW LEVEL SECURITY;
ALTER TABLE bids ENABLE ROW LEVEL SECURITY;
ALTER TABLE portfolios ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE gigs ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_messages ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Get the current user's database ID from their auth_id
CREATE OR REPLACE FUNCTION auth.user_id()
RETURNS BIGINT AS $$
  SELECT id FROM users WHERE auth_id = auth.uid();
$$ LANGUAGE SQL STABLE;

-- Check if current user is admin
CREATE OR REPLACE FUNCTION auth.is_admin()
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM users
    WHERE auth_id = auth.uid() AND role = 'admin'
  );
$$ LANGUAGE SQL STABLE;

-- Check if current user is a worker
CREATE OR REPLACE FUNCTION auth.is_worker()
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM users
    WHERE auth_id = auth.uid() AND role IN ('worker', 'tool_provider')
  );
$$ LANGUAGE SQL STABLE;

-- ============================================================================
-- 1. Users Table Policies
-- ============================================================================

-- Users can read their own profile
CREATE POLICY "Users can view own profile"
  ON users FOR SELECT
  USING (auth_id = auth.uid() OR auth.is_admin());

-- Users can update their own profile
CREATE POLICY "Users can update own profile"
  ON users FOR UPDATE
  USING (auth_id = auth.uid() OR auth.is_admin());

-- Allow registration (insert) - handled by auth.js with Supabase Auth
CREATE POLICY "Anyone can register"
  ON users FOR INSERT
  WITH CHECK (true);

-- Admins can see all users
CREATE POLICY "Admins can view all users"
  ON users FOR SELECT
  USING (auth.is_admin());

-- Workers can see client profiles for their jobs
CREATE POLICY "Workers can view clients they work with"
  ON users FOR SELECT
  USING (
    id IN (
      SELECT client_id FROM jobs
      WHERE assigned_worker_id = auth.user_id()
    )
  );

-- Clients can see worker profiles who bid on their jobs
CREATE POLICY "Clients can view workers who bid"
  ON users FOR SELECT
  USING (
    id IN (
      SELECT worker_id FROM bids
      WHERE job_id IN (SELECT id FROM jobs WHERE client_id = auth.user_id())
    )
  );

-- ============================================================================
-- 2. Categories Table Policies (Public Read-Only)
-- ============================================================================

CREATE POLICY "Anyone can view categories"
  ON categories FOR SELECT
  USING (true);

CREATE POLICY "Only admins can modify categories"
  ON categories FOR ALL
  USING (auth.is_admin());

-- ============================================================================
-- 3. Worker Profiles Table Policies
-- ============================================================================

-- Workers can view and update their own profile
CREATE POLICY "Workers can manage own profile"
  ON worker_profiles FOR ALL
  USING (worker_id = auth.user_id() OR auth.is_admin());

-- Clients can view verified worker profiles
CREATE POLICY "Clients can view verified workers"
  ON worker_profiles FOR SELECT
  USING (verification_status = 'verified' OR auth.is_admin());

-- Anyone can view verified worker profiles (for browsing)
CREATE POLICY "Public can view verified workers"
  ON worker_profiles FOR SELECT
  USING (verification_status = 'verified');

-- ============================================================================
-- 4. Jobs Table Policies
-- ============================================================================

-- Clients can manage their own jobs
CREATE POLICY "Clients can manage own jobs"
  ON jobs FOR ALL
  USING (client_id = auth.user_id() OR auth.is_admin());

-- Workers can view open jobs
CREATE POLICY "Workers can view open jobs"
  ON jobs FOR SELECT
  USING (status = 'open' OR auth.is_admin());

-- Workers can view jobs they've bid on
CREATE POLICY "Workers can view jobs they bid on"
  ON jobs FOR SELECT
  USING (
    id IN (
      SELECT job_id FROM bids WHERE worker_id = auth.user_id()
    )
  );

-- Workers can view jobs they're assigned to
CREATE POLICY "Workers can view assigned jobs"
  ON jobs FOR SELECT
  USING (assigned_worker_id = auth.user_id() OR auth.is_admin());

-- Workers can update jobs they're assigned to (status changes)
CREATE POLICY "Workers can update assigned jobs"
  ON jobs FOR UPDATE
  USING (assigned_worker_id = auth.user_id() OR auth.is_admin());

-- ============================================================================
-- 5. Job Images Table Policies
-- ============================================================================

-- Follow job visibility rules
CREATE POLICY "Job images follow job visibility"
  ON job_images FOR SELECT
  USING (
    job_id IN (SELECT id FROM jobs) -- RLS on jobs table handles visibility
    OR auth.is_admin()
  );

-- Clients can manage images for their jobs
CREATE POLICY "Clients can manage job images"
  ON job_images FOR ALL
  USING (
    job_id IN (SELECT id FROM jobs WHERE client_id = auth.user_id())
    OR auth.is_admin()
  );

-- ============================================================================
-- 6. Bids Table Policies
-- ============================================================================

-- Workers can create bids on open jobs
CREATE POLICY "Workers can create bids"
  ON bids FOR INSERT
  WITH CHECK (
    worker_id = auth.user_id()
    AND auth.is_worker()
    AND EXISTS (SELECT 1 FROM jobs WHERE id = job_id AND status = 'open')
  );

-- Workers can view their own bids
CREATE POLICY "Workers can view own bids"
  ON bids FOR SELECT
  USING (worker_id = auth.user_id() OR auth.is_admin());

-- Clients can view bids on their jobs
CREATE POLICY "Clients can view bids on own jobs"
  ON bids FOR SELECT
  USING (
    job_id IN (SELECT id FROM jobs WHERE client_id = auth.user_id())
    OR auth.is_admin()
  );

-- Clients can update bid status (accept/reject)
CREATE POLICY "Clients can update bid status"
  ON bids FOR UPDATE
  USING (
    job_id IN (SELECT id FROM jobs WHERE client_id = auth.user_id())
    OR auth.is_admin()
  );

-- ============================================================================
-- 7. Portfolios Table Policies
-- ============================================================================

-- Workers can manage their own portfolio
CREATE POLICY "Workers can manage own portfolio"
  ON portfolios FOR ALL
  USING (worker_id = auth.user_id() OR auth.is_admin());

-- Anyone can view portfolios (public showcase)
CREATE POLICY "Public can view portfolios"
  ON portfolios FOR SELECT
  USING (true);

-- ============================================================================
-- 8. Reviews Table Policies
-- ============================================================================

-- Users can create reviews for completed jobs
CREATE POLICY "Users can create reviews for completed jobs"
  ON reviews FOR INSERT
  WITH CHECK (
    reviewer_id = auth.user_id()
    AND EXISTS (
      SELECT 1 FROM jobs
      WHERE id = job_id
      AND status = 'completed'
      AND (client_id = auth.user_id() OR assigned_worker_id = auth.user_id())
    )
  );

-- Anyone can view reviews (public feedback)
CREATE POLICY "Public can view reviews"
  ON reviews FOR SELECT
  USING (true);

-- Reviewers can update their own reviews
CREATE POLICY "Reviewers can update own reviews"
  ON reviews FOR UPDATE
  USING (reviewer_id = auth.user_id() OR auth.is_admin());

-- ============================================================================
-- 9. Payments Table Policies
-- ============================================================================

-- Clients can view their own payments
CREATE POLICY "Clients can view own payments"
  ON payments FOR SELECT
  USING (client_id = auth.user_id() OR auth.is_admin());

-- Workers can view payments for their jobs
CREATE POLICY "Workers can view received payments"
  ON payments FOR SELECT
  USING (worker_id = auth.user_id() OR auth.is_admin());

-- Only system/admin can create payments (via backend)
CREATE POLICY "System can create payments"
  ON payments FOR INSERT
  WITH CHECK (auth.is_admin());

-- Only admin can update payment status
CREATE POLICY "Admins can update payments"
  ON payments FOR UPDATE
  USING (auth.is_admin());

-- ============================================================================
-- 10. Gigs Table Policies
-- ============================================================================

-- Workers can manage their own gigs
CREATE POLICY "Workers can manage own gigs"
  ON gigs FOR ALL
  USING (worker_id = auth.user_id() OR auth.is_admin());

-- Anyone can view active gigs (marketplace)
CREATE POLICY "Public can view active gigs"
  ON gigs FOR SELECT
  USING (status = 'active' OR auth.is_admin());

-- ============================================================================
-- 11. Messages Table Policies
-- ============================================================================

-- Users can view messages they sent or received
CREATE POLICY "Users can view own messages"
  ON messages FOR SELECT
  USING (
    sender_id = auth.user_id()
    OR receiver_id = auth.user_id()
    OR auth.is_admin()
  );

-- Users can send messages for jobs they're involved in
CREATE POLICY "Users can send messages"
  ON messages FOR INSERT
  WITH CHECK (
    sender_id = auth.user_id()
    AND EXISTS (
      SELECT 1 FROM jobs
      WHERE id = job_id
      AND (
        client_id = auth.user_id()
        OR assigned_worker_id = auth.user_id()
        OR id IN (SELECT job_id FROM bids WHERE worker_id = auth.user_id())
      )
    )
  );

-- Users can mark their received messages as read
CREATE POLICY "Users can update received messages"
  ON messages FOR UPDATE
  USING (receiver_id = auth.user_id() OR auth.is_admin());

-- ============================================================================
-- 12. Contact Messages Table Policies
-- ============================================================================

-- Anyone can submit contact messages
CREATE POLICY "Anyone can submit contact messages"
  ON contact_messages FOR INSERT
  WITH CHECK (true);

-- Only admins can view and manage contact messages
CREATE POLICY "Admins can manage contact messages"
  ON contact_messages FOR ALL
  USING (auth.is_admin());

-- ============================================================================
-- Grant appropriate permissions to authenticated users
-- ============================================================================

GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- ============================================================================
-- Notes for Production Deployment
-- ============================================================================
-- 1. Test these policies thoroughly in a staging environment
-- 2. Monitor Supabase logs for unauthorized access attempts
-- 3. Review and audit policies quarterly
-- 4. Consider adding rate limiting for public endpoints
-- 5. Implement audit logging for sensitive operations
-- ============================================================================
